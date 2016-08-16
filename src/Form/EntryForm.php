<?php

namespace Drupal\tfa\Form;

use Drupal\Core\Form\FormBase;
use Drupal\Core\Form\FormStateInterface;
use Drupal\Core\Session\AccountInterface;
use Drupal\tfa\TfaLoginPluginManager;
use Drupal\tfa\TfaValidationPluginManager;
use Symfony\Component\DependencyInjection\ContainerInterface;

/**
 * TFA entry form.
 */
class EntryForm extends FormBase {

  /**
   * Validation plugin manager.
   *
   * @var \Drupal\tfa\TfaValidationPluginManager
   */
  protected $tfaValidationManager;

  /**
   * Login plugin manager.
   *
   * @var \Drupal\tfa\TfaLoginPluginManager
   */
  protected $tfaLoginManager;

  /**
   * The validation plugin object.
   *
   * @var \Drupal\tfa\Plugin\TfaValidationInterface
   */
  protected $tfaValidationPlugin;

  /**
   * The login plugins.
   *
   * @var \Drupal\tfa\Plugin\TfaLoginInterface
   */
  protected $tfaLoginPlugins;

  /**
   * The fallback plugin object.
   *
   * @var \Drupal\tfa\Plugin\TfaValidationInterface
   */
  protected $tfaFallbackPlugin;

  /**
   * EntryForm constructor.
   *
   * @param \Drupal\tfa\TfaValidationPluginManager $tfa_validation_manager
   *   Plugin manager for validation plugins.
   * @param \Drupal\tfa\TfaLoginPluginManager $tfa_login_manager
   *   Plugin manager for login plugins.
   */
  public function __construct(TfaValidationPluginManager $tfa_validation_manager, TfaLoginPluginManager $tfa_login_manager) {
    $this->tfaValidationManager = $tfa_validation_manager;
    $this->tfaLoginManager = $tfa_login_manager;
  }

  /**
   * Creates service objects for the class contructor.
   *
   * @param \Symfony\Component\DependencyInjection\ContainerInterface $container
   *   The container to get the required services.
   *
   * @return static
   */
  public static function create(ContainerInterface $container) {
    return new static(
      $container->get('plugin.manager.tfa.validation'),
      $container->get('plugin.manager.tfa.login')
      );
  }

  /**
   * {@inheritdoc}
   */
  public function getFormId() {
    return 'tfa_entry_form';
  }

  /**
   * {@inheritdoc}
   */
  public function buildForm(array $form, FormStateInterface $form_state, AccountInterface $user = NULL) {
    // Check flood tables.
    // @TODO Reimplement Flood Controls.
    //    if (_tfa_hit_flood($tfa)) {
    //      \Drupal::moduleHandler()->invokeAll('tfa_flood_hit', [$tfa->getContext()]);
    //      return drupal_access_denied();
    //    }
    //
    // Get TFA plugins form.
    $validate_plugin = $this->config('tfa.settings')->get('validate_plugin');
    $this->tfaValidationPlugin = $this->tfaValidationManager->createInstance($validate_plugin, ['uid' => $user->id()]);
    $form = $this->tfaValidationPlugin->getForm($form, $form_state);


    if ($this->tfaLoginPlugins = $this->tfaLoginManager->getPlugins(['uid' => $user->id()])) {
      foreach ($this->tfaLoginPlugins as $login_plugin) {
        if (method_exists($login_plugin, 'getForm')) {
          $form = $login_plugin->getForm($form, $form_state);
        }
      }
    }

    $form['account'] = [
      '#type' => 'value',
      '#value' => $user,
    ];

    return $form;


  }

  /**
   * {@inheritdoc}
   */
  public function validateForm(array &$form, FormStateInterface $form_state) {
    $validated = $this->tfaValidationPlugin->validateForm($form, $form_state);
    $config = $this->config('tfa.settings');
    $fallbacks = $config->get('fallback_plugins');
    $values = $form_state->getValues();

    if (!$validated && isset($fallbacks[$config->get('validation_plugin')])) {
      $form_state->clearErrors();
      $errors = $this->tfaValidationPlugin->getErrorMessages();
      $form_state->setErrorByName(key($errors), current($errors));
      foreach ($fallbacks[$config->get('validation_plugin')] as $fallback => $val) {
        $fallback_plugin = $this->tfaValidationManager->createInstance($fallback, ['uid' => $values['account']->id()]);
        if (!$fallback_plugin->validateForm($form, $form_state)) {
          $errors = $fallback_plugin->getErrorMessages();
          $form_state->setErrorByName(key($errors), current($errors));
        }
        else {
          $form_state->clearErrors();
          break;
        }
      }
    }

    if (!empty($this->tfaLoginPlugins)) {
      foreach ($this->tfaLoginPlugins as $login_plugin) {
        if (method_exists($login_plugin, 'validateForm')) {
          $login_plugin->validateForm($form, $form_state);
        }
      }
    }
  }

  /**
   * For the time being, assume there is no fallback options available.
   * If the form is submitted and passes validation, the user should be able
   * to log in.
   *
   * {@inheritdoc}
   */
  public function submitForm(array &$form, FormStateInterface $form_state) {
    $user = $form_state->getValue('account');
    // TODO This could be improved with EventDispatcher.
    if (!empty($this->tfaLoginPlugins)) {
      foreach ($this->tfaLoginPlugins as $plugin) {
        if (method_exists($plugin, 'submitForm')) {
          $plugin->submitForm($form, $form_state);
        }
      }
    }

    user_login_finalize($user);

    // TODO Should finalize() be after user_login_finalize or before?!
    // TODO This could be improved with EventDispatcher.
    $this->finalize();

    $form_state->setRedirect('<front>');
  }

  /**
   * Run TFA process finalization.
   */
  public function finalize() {
    // Invoke plugin finalize.
    if (method_exists($this->tfaValidationPlugin, 'finalize')) {
      $this->tfaValidationPlugin->finalize();
    }
    // Allow login plugins to act during finalization.
    if (!empty($this->tfaLoginPlugins)) {
      foreach ($this->tfaLoginPlugins as $plugin) {
        if (method_exists($plugin, 'finalize')) {
          $plugin->finalize();
        }
      }
    }
  }

  /**
   * {@inheritdoc}
   */
  protected function getEditableConfigNames() {
    return ['tfa.settings'];
  }

}
