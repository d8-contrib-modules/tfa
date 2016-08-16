<?php

namespace Drupal\tfa\Plugin\TfaValidation;

use Base32\Base32;
use Drupal\Core\Form\FormStateInterface;
use Drupal\encrypt\EncryptionProfileManagerInterface;
use Drupal\encrypt\EncryptServiceInterface;
use Drupal\tfa\Plugin\TfaBasePlugin;
use Drupal\tfa\Plugin\TfaValidationInterface;
use Drupal\user\UserDataInterface;
use Otp\GoogleAuthenticator;
use Otp\Otp;
use Symfony\Component\DependencyInjection\ContainerInterface;

/**
 * HOTP validation class for performing HOTP validation.
 *
 * @TfaValidation(
 *   id = "tfa_hotp",
 *   label = @Translation("TFA Hmac-based OTP(HOTP)"),
 *   description = @Translation("TFA Hotp Validation Plugin"),
 *   fallbacks = {
 *    "tfa_recovery_code"
 *   },
 *   isFallback = FALSE
 * )
 */
class TfaHotp extends TfaBasePlugin implements TfaValidationInterface {
  /**
   * Object containing the external validation library.
   *
   * @var GoogleAuthenticator
   */
  protected $auth;

  /**
   * The counter window in which the validation should be done.
   *
   * @var int
   */
  protected $counterWindow;

  /**
   * Name prefix.
   *
   * @var string
   */
  protected $namePrefix;

  /**
   * Whether the code has already been used or not.
   *
   * @var bool
   */
  protected $alreadyAccepted;

  /**
   * {@inheritdoc}
   */
  public function __construct(array $configuration, $plugin_id, $plugin_definition, UserDataInterface $user_data, EncryptionProfileManagerInterface $encryption_profile_manager, EncryptServiceInterface $encrypt_service) {
    parent::__construct($configuration, $plugin_id, $plugin_definition, $user_data, $encryption_profile_manager, $encrypt_service);
    $this->auth      = new \StdClass();
    $this->auth->otp = new Otp();
    $this->auth->ga  = new GoogleAuthenticator();
    $this->alreadyAccepted = FALSE;
    $settings = \Drupal::config('tfa.settings')->get('validation_plugin_settings')['tfa_hotp'];
    $this->counterWindow = $settings['counter_window'];
    $this->namePrefix = $settings['name_prefix'];
  }

  /**
   * {@inheritdoc}
   */
  public static function create(ContainerInterface $container, array $configuration, $plugin_id, $plugin_definition) {
    return new static(
      $configuration,
      $plugin_id,
      $plugin_definition,
      $container->get('user.data'),
      $container->get('encrypt.encryption_profile.manager'),
      $container->get('encryption')
    );
  }

  /**
   * {@inheritdoc}
   */
  public function ready() {
    return ($this->getSeed() !== FALSE);
  }

  /**
   * {@inheritdoc}
   */
  public function getForm(array $form, FormStateInterface $form_state) {
    $message = 'Verification code is application generated and @length digits long.';
    if ($this->getUserData('tfa', 'tfa_recovery_code', $this->uid, $this->userData) && $this->getFallbacks()) {
      $message .= '<br/>Can not access your account? Use one of your recovery codes.';
    }
    $form['code'] = [
      '#type' => 'textfield',
      '#title' => t('Application verification code'),
      '#description' => t($message, ['@length' => $this->codeLength]),
      '#required'  => TRUE,
      '#attributes' => ['autocomplete' => 'off'],
    ];
    $form['actions']['#type'] = 'actions';
    $form['actions']['login'] = [
      '#type'  => 'submit',
      '#value' => t('Verify'),
    ];
    return $form;
  }

  public function buildConfigurationForm($config, $state) {
    $settings_form['counter_window'] = [
      '#type' => 'textfield',
      '#title' => t('Counter Window'),
      '#default_value' => ($this->counterWindow) ?: 5,
      '#description' => 'How far ahead from current counter should we check the code.',
      '#size' => 2,
      '#states' => $state,
      '#required' => TRUE,
    ];

    $settings_form['name_prefix'] = [
      '#type' => 'textfield',
      '#title' => t('OTP QR Code Prefix'),
      '#default_value' => ($this->namePrefix) ?: 'tfa',
      '#description' => 'Prefix for OTP QR code names. Suffix is account username.',
      '#size' => 15,
      '#states' => $state,
      '#required' => TRUE,
    ];

    return $settings_form;
  }

  /**
   * {@inheritdoc}
   */
  public function validateForm(array $form, FormStateInterface $form_state) {
    $values = $form_state->getValues();
    // dpm($values);
    if (!$this->validate($values['code'])) {
      $this->errorMessages['code'] = t('Invalid application code. Please try again.');
      if ($this->alreadyAccepted) {
        $form_state->clearErrors();
        $this->errorMessages['code'] = t('Invalid code, it was recently used for a login. Please try a new code.');
      }
      return FALSE;
    }
    else {
      // Store accepted code to prevent replay attacks.
      $this->storeAcceptedCode($values['code']);
      return TRUE;
    }
  }

  /**
   * Simple validate for web services.
   *
   * @param int $code
   *   OTP Code.
   *
   * @return bool
   *   True if validation was successful otherwise false.
   */
  public function validateRequest($code) {
    if ($this->validate($code)) {
      $this->storeAcceptedCode($code);
      return TRUE;
    }

    return FALSE;
  }

  /**
   * {@inheritdoc}
   */
  protected function validate($code) {
    // Strip whitespace.
    $code = preg_replace('/\s+/', '', $code);
    if ($this->alreadyAcceptedCode($code)) {
      $this->isValid = FALSE;
    }
    else {
      // Get OTP seed.
      $seed = $this->getSeed();
      $counter = $this->getHotpCounter();
      $this->isValid = ($seed && ($counter = $this->auth->otp->checkHotpResync(Base32::decode($seed), $counter, $code)));
      $this->setUserData('tfa', ['tfa_hotp_counter' => ++$counter], $this->uid, $this->userData);
    }
    return $this->isValid;
  }

  /**
   * Returns whether code has already been used or not.
   *
   * @return bool
   *   True is code already used otherwise false.
   */
  public function isAlreadyAccepted() {
    return $this->alreadyAccepted;
  }

  /**
   * Get seed for this account.
   *
   * @return string
   *    Decrypted account OTP seed or FALSE if none exists.
   */
  protected function getSeed() {
    // Lookup seed for account and decrypt.
    $result = $this->getUserData('tfa', 'tfa_hotp_seed', $this->uid, $this->userData);

    if (!empty($result)) {
      $encrypted = base64_decode($result['seed']);
      $seed      = $this->decrypt($encrypted);
      if (!empty($seed)) {
        return $seed;
      }
    }
    return FALSE;
  }

  /**
   * Save seed for account.
   *
   * @param string $seed
   *   Un-encrypted seed.
   */
  public function storeSeed($seed) {
    // Encrypt seed for storage.
    $encrypted = $this->encrypt($seed);

    $record = [
      'tfa_hotp_seed' => [
        'seed' => base64_encode($encrypted),
        'created' => REQUEST_TIME,
      ],
    ];
    $this->setUserData('tfa', $record, $this->uid, $this->userData);
  }

  /**
   * Delete the seed of the current validated user.
   */
  protected function deleteSeed() {
    $this->deleteUserData('tfa', 'tfa_hotp_seed', $this->uid, $this->userData);
  }

  /**
   * Get the HOTP counter.
   *
   * @return int
   *   The current value of the HOTP counter, or 1 if no value was found.
   */
  public function getHotpCounter() {
    $result = ($this->getUserData('tfa', 'tfa_hotp_counter', $this->uid, $this->userData)) ?: 1;

    return $result;
  }

  /**
   * {@inheritdoc}
   */
  public function getFallbacks() {
    return ($this->getPluginDefinition()['fallbacks']) ?: '';
  }

  /**
   * {@inheritdoc}
   */
  public function isFallback() {
    return ($this->getPluginDefinition()['isFallback']) ?: FALSE;
  }

}
