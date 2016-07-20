<?php

namespace Drupal\tfa\Plugin\TfaValidation;

use Drupal\Core\DependencyInjection\DependencySerializationTrait;
use Drupal\Core\Form\FormStateInterface;
use Drupal\encrypt\EncryptionProfileManagerInterface;
use Drupal\encrypt\EncryptService;
use Drupal\tfa\Plugin\TfaBasePlugin;
use Drupal\tfa\Plugin\TfaValidationInterface;
use Drupal\tfa\TfaDataTrait;
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
 *   description = @Translation("TFA Recovery Code Validation Plugin")
 * )
 */
class TfaRecoveryCode extends TfaBasePlugin implements TfaValidationInterface {
  use DependencySerializationTrait;
  use TfaDataTrait;

  /**
   * Object containing the external validation library.
   *
   * @var GoogleAuthenticator
   */
  protected $auth;

  /**
   * {@inheritdoc}
   */
  public function __construct(array $configuration, $plugin_id, $plugin_definition, UserDataInterface $user_data, EncryptionProfileManagerInterface $encryption_profile_manager, EncryptService $encrypt_service) {
    parent::__construct($configuration, $plugin_id, $plugin_definition, $user_data, $encryption_profile_manager, $encrypt_service);
    $this->auth      = new \StdClass();
    $this->auth->otp = new Otp();
    $this->auth->ga  = new GoogleAuthenticator();
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
    $form['recover'] = array(
      '#type' => 'textfield',
      '#title' => t('Enter one of your recovery codes'),
      '#required' => TRUE,
      '#description' => t('Recovery codes were generated when you first set up TFA. Format: XXX XX XXX'),
      '#attributes' => array('autocomplete' => 'off'),
    );
    $form['actions']['#type'] = 'actions';
    $form['actions']['login'] = array(
      '#type' => 'submit',
      '#value' => t('Verify'),
    );
    return $form;
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
   * {@inheritdoc}
   */
  public function finalize() {
    // Mark code as used.
    if ($this->usedCode) {
      $num = db_update('tfa_recovery_code')
        ->fields(array('used' => REQUEST_TIME))
        ->condition('id', $this->usedCode)
        ->condition('uid', $this->context['uid'])
        ->execute();
      if ($num) {
        watchdog('tfa_basic', 'Used TFA recovery code !id by user !uid', array('!id' => $this->usedCode, '!uid' => $this->context['uid']), WATCHDOG_NOTICE);
      }
    }
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
  public function purge() {
    $this->deleteCodes();
  }

}
