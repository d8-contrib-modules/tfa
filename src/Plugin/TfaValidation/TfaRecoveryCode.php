<?php

namespace Drupal\tfa\Plugin\TfaValidation;

use Drupal\Core\Form\FormStateInterface;
use Drupal\encrypt\EncryptionProfileManagerInterface;
use Drupal\encrypt\EncryptService;
use Drupal\encrypt\EncryptServiceInterface;
use Drupal\tfa\Plugin\TfaBasePlugin;
use Drupal\tfa\Plugin\TfaValidationInterface;
use Drupal\user\UserDataInterface;
use Otp\GoogleAuthenticator;
use Otp\Otp;
use Symfony\Component\DependencyInjection\ContainerInterface;

/**
 * Recovery validation class for performing recovery codes validation.
 *
 * @TfaValidation(
 *   id = "tfa_recovery_code",
 *   label = @Translation("TFA Recovery Code"),
 *   description = @Translation("TFA Recovery Code Validation Plugin"),
 *   isFallback = TRUE
 * )
 */
class TfaRecoveryCode extends TfaBasePlugin implements TfaValidationInterface {
  /**
   * The number of recovery codes to generate.
   *
   * @var int
   */
  protected $codeLimit;

  /**
   * Object containing the external validation library.
   *
   * @var GoogleAuthenticator
   */
  protected $auth;

  /**
   * {@inheritdoc}
   */
  public function __construct(array $configuration, $plugin_id,
    $plugin_definition, UserDataInterface $user_data, EncryptionProfileManagerInterface $encryption_profile_manager, EncryptServiceInterface $encrypt_service) {
    parent::__construct($configuration, $plugin_id, $plugin_definition, $user_data, $encryption_profile_manager, $encrypt_service);
    $this->auth      = new \StdClass();
    $this->auth->otp = new Otp();
    $this->auth->ga  = new GoogleAuthenticator();
    $validation_plugin = \Drupal::config('tfa.settings')->get('validation_plugin');
    $settings = \Drupal::config('tfa.settings')->get('fallback_plugins');
    $this->codeLimit = $settings[$validation_plugin]['tfa_recovery_code']['settings']['recovery_codes_amount'];
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
    $codes = $this->getCodes();
    return !empty($codes);
  }

  /**
   * {@inheritdoc}
   */
  public function getForm(array $form, FormStateInterface $form_state) {
    $form['recover'] = [
      '#type' => 'textfield',
      '#title' => t('Enter one of your recovery codes'),
      '#required' => TRUE,
      '#description' => t('Recovery codes were generated when you first set up TFA. Format: XXX XX XXX'),
      '#attributes' => ['autocomplete' => 'off'],
    ];
    $form['actions']['#type'] = 'actions';
    $form['actions']['login'] = [
      '#type' => 'submit',
      '#value' => t('Verify'),
    ];
    return $form;
  }

  public function buildConfigurationForm($config, $state) {
    $settings_form['recovery_codes_amount'] = [
      '#type' => 'textfield',
      '#title' => t('Recovery Codes Amount'),
      '#default_value' => ($this->codeLimit) ?: 10,
      '#description' => 'Number of Recovery Codes To Generate.',
      '#size' => 2,
      '#states' => $state,
      '#required' => TRUE
    ];

    return $settings_form;
  }

  /**
   * {@inheritdoc}
   */
  public function validateForm(array $form, FormStateInterface $form_state) {
    $values = $form_state->getValues();
    return $this->validate($values['code']);
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
   * Get unused recovery codes.
   *
   * @todo consider returning used codes so validate() can error with
   * appropriate message
   *
   * @return array
   *   Array of codes indexed by ID.
   */
  public function getCodes() {
    $codes = $this->getUserData('tfa', 'tfa_recovery_code', $this->uid, $this->userData) ?: [];
    array_walk($codes, function(&$v, $k) {
      $v = $this->decrypt($v);
    });
    return $codes;
  }

  /**
   * Save recovery codes for current account.
   *
   * @param array $codes
   *   Recovery codes for current account.
   */
  public function storeCodes($codes) {
    $this->deleteCodes();

    // Encrypt code for storage.
    array_walk($codes, function(&$v, $k) {
      $v = $this->encrypt($v);
    });
    $data = ['tfa_recovery_code' => $codes];

    $this->setUserData('tfa', $data, $this->uid, $this->userData);

    // $message = 'Saved recovery codes for user %uid';
    // if ($num_deleted) {
    //  $message .= ' and deleted 1 old code';
    // }
    // \Drupal::logger('tfa')->info($message, ['%uid' => $this->configuration['uid']]);.
  }

  /**
   * Delete existing codes.
   */
  protected function deleteCodes() {
    // Delete any existing codes.
    $this->deleteUserData('tfa', 'tfa_recovery_code', $this->uid, $this->userData);
  }

  /**
   * {@inheritdoc}
   */
  protected function validate($code) {
    $this->isValid = FALSE;
    // Get codes and compare.
    $codes = $this->getCodes();
    if (empty($codes)) {
      $this->errorMessages['recovery_code'] = t('You have no unused codes available.');
      return FALSE;
    }
    // Remove empty spaces.
    $code = str_replace(' ', '', $code);
    foreach ($codes as $id => $stored) {
      // Remove spaces from stored code.
      if (trim(str_replace(' ', '', $stored)) === $code) {
        $this->isValid = TRUE;
        unset($codes[$id]);
        $this->storeCodes($codes);
        return $this->isValid;
      }
    }
    $this->errorMessages['recovery_code'] = t('Invalid recovery code.');
    return $this->isValid;
  }

  /**
   * {@inheritdoc}
   */
  public function getFallbacks() {
    return ($this->pluginDefinition['fallbacks']) ?: '';
  }

  /**
   * {@inheritdoc}
   */
  public function isFallback() {
    return ($this->pluginDefinition['isFallback']) ?: FALSE;
  }

}
