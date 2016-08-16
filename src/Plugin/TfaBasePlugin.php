<?php

namespace Drupal\tfa\Plugin;

use Drupal\Component\Plugin\PluginBase;
use Drupal\Core\DependencyInjection\DependencySerializationTrait;
use Drupal\Core\Form\FormStateInterface;
use Drupal\Core\Site\Settings;
use Drupal\encrypt\EncryptionProfileManagerInterface;
use Drupal\encrypt\EncryptServiceInterface;
use Drupal\tfa\TfaDataTrait;
use Drupal\user\UserDataInterface;

/**
 * Base plugin class.
 */
abstract class TfaBasePlugin extends PluginBase {
  use DependencySerializationTrait;
  use TfaDataTrait;

  /**
   * The user submitted code to be validated.
   *
   * @var string
   */
  protected $code;

  /**
   * The allowed code length.
   *
   * @var int
   */
  protected $codeLength;

  /**
   * The error for the current validation.
   *
   * @var string[]
   */
  protected $errorMessages;

  /**
   * Whether the validation succeeded or not.
   *
   * @var bool
   */
  protected $isValid;

  /**
   * Whether the code has been used before.
   *
   * @var string
   */
  protected $alreadyAccepted;

  /**
   * Provides the user data service object.
   *
   * @var \Drupal\user\UserDataInterface
   */
  protected $userData;

  /**
   * The user id.
   *
   * @var int
   */
  protected $uid;

  /**
   * Encryption profile.
   *
   * @var \Drupal\encrypt\EncryptionProfileManagerInterface
   */
  protected $encryptionProfile;

  /**
   * Encryption service.
   *
   * @var \Drupal\encrypt\EncryptService
   */
  protected $encryptService;

  /**
   * Constructs a new Tfa plugin object.
   *
   * @param array $configuration
   *    The plugin configuration.
   * @param string $plugin_id
   *    The plugin id.
   * @param mixed $plugin_definition
   *    The plugin definition.
   * @param \Drupal\user\UserDataInterface $user_data
   *    User data object to store user specific information.
   * @param \Drupal\encrypt\EncryptionProfileManagerInterface $encryption_profile_manager
   *   Encryption profile manager.
   * @param \Drupal\encrypt\EncryptServiceInterface $encrypt_service
   *   Encryption service.
   */
  public function __construct(array $configuration, $plugin_id, $plugin_definition, UserDataInterface $user_data, EncryptionProfileManagerInterface $encryption_profile_manager, EncryptServiceInterface $encrypt_service) {
    parent::__construct($configuration, $plugin_id, $plugin_definition);
    // Default code length is 6.
    $this->codeLength = 6;
    $this->isValid = FALSE;

    // User Data service to store user-based data in key value pairs.
    $this->userData = $user_data;

    // Encryption profile manager and service.
    $encryptionProfileId = \Drupal::config('tfa.settings')->get('encryption');
    $this->encryptionProfile = $encryption_profile_manager->getEncryptionProfile($encryptionProfileId);
    $this->encryptService = $encrypt_service;
    $this->uid = $this->configuration['uid'];
  }

  /**
   * Determine if the plugin can run for the current TFA context.
   *
   * @return bool
   *    True or False based on the checks performed.
   */
  abstract public function ready();

  /**
   * Get error messages suitable for form_set_error().
   *
   * @return array
   *   An array of error strings.
   */
  public function getErrorMessages() {
    return $this->errorMessages;
  }

  /**
   * Submit form.
   *
   * @param array $form
   *   An associative array containing the structure of the form.
   * @param \Drupal\Core\Form\FormStateInterface $form_state
   *   The current state of the form.
   *
   * @return bool Whether plugin form handling is complete.
   *   Plugins should return FALSE to invoke multi-step.
   */
  public function submitForm(array $form, FormStateInterface &$form_state) {
    return $this->isValid;
  }

  /**
   * Validate code.
   *
   * Note, plugins overriding validate() should be sure to set isValid property
   * correctly or else also override submitForm().
   *
   * @param string $code
   *   Code to be validated.
   *
   * @return bool
   *    Whether code is valid.
   */
  protected function validate($code) {
    if ((string) $code === (string) $this->code) {
      $this->isValid = TRUE;
      return TRUE;
    }
    else {
      return FALSE;
    }
  }

  /**
   * Encrypt a plaintext string.
   *
   * Should be used when writing codes to storage.
   *
   * @param string $data
   *   The string to be encrypted.
   *
   * @return string
   *   The enrcypted string.
   */
  protected function encrypt($data) {
    return $this->encryptService->encrypt($data, $this->encryptionProfile);
  }

  /**
   * Decrypt a encrypted string.
   *
   * Should be used when reading codes from storage.
   *
   * @param string $data
   *   The string to be decrypted.
   *
   * @return string
   *   The decrypted string.
   */
  protected function decrypt($data) {
    return $this->encryptService->decrypt($data, $this->encryptionProfile);
  }

  /**
   * Store validated code to prevent replay attack.
   *
   * @param string $code
   *    The validated code.
   */
  protected function storeAcceptedCode($code) {
    $code = preg_replace('/\s+/', '', $code);
    $hash = hash('sha1', Settings::getHashSalt() . $code);

    // Store the hash made using the code in users_data.
    $store_data = ['tfa_accepted_code_' . $hash => REQUEST_TIME];
    $this->setUserData('tfa', $store_data, $this->uid, $this->userData);
  }

  /**
   * Whether code has already been used.
   *
   * @param string $code
   *    The code to be checked.
   *
   * @return bool
   *    TRUE if already used otherwise FALSE
   */
  protected function alreadyAcceptedCode($code) {
    $hash = hash('sha1', Settings::getHashSalt() . $code);
    // Check if the code has already been used or not.
    $key    = 'tfa_accepted_code_' . $hash;
    $result = $this->getUserData('tfa', $key, $this->uid, $this->userData);
    if (!empty($result)) {
      $this->alreadyAccepted = TRUE;
      return TRUE;
    }
    return FALSE;
  }

  /**
   * Get the plugin label.
   *
   * @return string
   *   The plugin label.
   */
  public function getLabel() {
    return ($this->pluginDefinition['label']) ?: '';
  }

}
