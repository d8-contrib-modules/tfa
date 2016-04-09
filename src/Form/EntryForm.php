<?php

/**
 * @file
 * Contains Drupal\tfa\Form\EntryForm.
 */

namespace Drupal\tfa\Form;

use Drupal\Core\Form\FormBase;
use Drupal\Core\Form\FormStateInterface;
use Drupal\Core\Session\AccountInterface;
use Drupal\tfa\Plugin\TfaValidationInterface;
use Drupal\tfa\Plugin\TfaBasePlugin;
use Drupal\tfa\TfaLoginPluginManager;
use Drupal\tfa\TfaValidationPluginManager;
use Symfony\Component\DependencyInjection\ContainerInterface;

class EntryForm extends FormBase {

  /**
   * @var \Drupal\tfa\TfaManager
   */
  protected $tfaValidationManager;
  protected $tfaLoginManager;
  protected $tfaValidationPlugin;
  protected $tfaLoginPlugins;
  protected $tfaFallbackPlugin;
  protected $tfaSettings;
  protected $tfaBasePlugin;


  public function __construct(TfaValidationPluginManager $tfa_validation_manager, TfaLoginPluginManager $tfa_login_manager, TfaBasePlugin $tfaBasePlugin) {
    $this->tfaValidationManager = $tfa_validation_manager;
    $this->tfaLoginManager = $tfa_login_manager;
    $this->tfaSettings = \Drupal::config('tfa.settings');
    $this->tfaBasePlugin= $tfaBasePlugin;

  }

  public static function create(ContainerInterface $container) {
    return new static(
      $container->get('plugin.manager.tfa.validation'),
      $container->get('plugin.manager.tfa.login'),
      $container->get('plugin.manager.tfa.base')
      );
  }


  /**
   * {@inheritdoc}
   */
  public function getFormID() {
    return 'tfa_entry_form';
  }

  /**
   * {@inheritdoc}
   */
  public function buildForm(array $form, FormStateInterface $form_state, AccountInterface $user = null) {
    // Check flood tables.

    if ($this->_tfa_hit_flood()) {
     // \Drupal::moduleHandler()->invokeAll('tfa_flood_hit', [$tfa->getContext()]);
//      return drupal_access_denied();
    }


    // Get TFA plugins form.
    $this->tfaValidationPlugin = $this->tfaValidationManager->getInstance(['uid' => $user->id()]);
    $form =  $this->tfaValidationPlugin->getForm($form, $form_state);

    if ($this->tfaLoginPlugins = $this->tfaLoginManager->getPlugins(['uid' => $user->id()])) {
      foreach ($this->tfaLoginPlugins as $login_plugin) {
        if (method_exists($login_plugin, 'getForm')) {
          $form = $login_plugin->getForm($form, $form_state);
        }
      }
    }

  //@TODO Add $fallback plugin capabilities.
    //If there is a fallback method, set it.
//    if ($tfa->hasFallback()) {
//      $form['actions']['fallback'] = array(
//        '#type' => 'submit',
//        '#value' => t("Can't access your account?"),
//        '#submit' => array('tfa_form_submit'),
//        '#limit_validation_errors' => array(),
//        '#weight' => 20,
//      );
//    }

    // Set account element.
    $form['account'] = array(
      '#type' => 'value',
      '#value' => $user,
    );

    return $form;
  }

  /**
   * {@inheritdoc}
   */
  public function validateForm(array &$form, FormStateInterface $form_state) {
    $this->tfaValidationPlugin->validateForm($form, $form_state);
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
    //If validation failed or fallback was requested.
    //if($form_state->hasAnyErrors()) {
      // If fallback was triggered TFA process has been reset to new validate
      // plugin so run begin and store new context.

//      $fallback = $form_state->getValue('fallback');
//      if (isset($fallback) && $form_state->getValue('op') === $fallback) {
//        $tfa->begin();
//      }
      //$context = $tfa->getContext();
      //$this->tfaManager->setContext($user, $context);
      //$form_state['rebuild'] = TRUE;
    //}
    //else {
    // TFA process is complete so finalize and authenticate user.
    //$context = $this->tfaManager->getContext($user);

    // TODO This could be improved with EventDispatcher
    if (!empty($this->tfaLoginPlugins)) {
      foreach ($this->tfaLoginPlugins as $plugin) {
        if (method_exists($plugin, 'submitForm')) {
          $plugin->submitForm($form, $form_state);
        }
      }
    }

    user_login_finalize($user);

    // TODO Should finalize() be after user_login_finalize or before?!
    // TODO This could be improved with EventDispatcher
    $this->finalize();


    // Set redirect based on query parameters, existing $form_state or context.
    //$form_state['redirect'] = _tfa_form_get_destination($context, $form_state, $user);
    $form_state->setRedirect('<front>');
    //}
  }

  /**
   * Checks if user is allowed to continue with plugin action.
   *
   * @param string $window
   * @return bool
   */
  public function floodIsAllowed($window = '') {
    if (method_exists($this->tfaBasePlugin, 'floodIsAllowed')) {
      return $this->tfaBasePlugin->floodIsAllowed($window);
    }
    return TRUE;
  }

  /**
   * Check if flood has been hit.
   *
   * @return bool
   */

  public function _tfa_hit_flood() {

    if ($this->tfaSettings->get('tfa_test_mode')) {
      return FALSE;
    }
    $window = $this->tfaSettings->get('tfa_flood_window');
    $user_window = $this->tfaSettings->get('tfa_user_window');
    $flood_config = $this->config('user.flood');
    //$context = $tfa->getContext();
    if ($flood_config->get('uid_only')) {
      // Register flood events based on the uid only, so they apply for any
      // IP address. This is the most secure option.
      //$identifier = context['uid'];
    }
    else {
      // The default identifier is a combination of uid and IP address. This
      // is less secure but more resistant to denial-of-service attacks that
      // could lock out all users with public user names.
     // $identifier = context['uid'] . '-' . $this->getRequest()->getClientIP();
    }


    // Check user specific flood
    if (!\Drupal::flood()->isAllowed('tfa_user', $this->tfaSettings->get('tfa_user_threshold'), $user_window, $identifier)) {
      drupal_set_message(t('You have reached the threshold for incorrect code entry attempts. Please try again in !time minutes.', array('!time' => round($user_window / 60))), 'error');
      return TRUE;
    }
    // Check entire process flood.
    elseif (!\Drupal::flood()->isAllowed('tfa_begin', $this->tfaSettings->get('tfa_begin_threshold'), $window)) {
      drupal_set_message(t('You have reached the threshold for TFA attempts. Please try again in !time minutes.', array('!time' => round($window / 60))), 'error');
      return TRUE;
    }
    // Check TFA plugin flood.
    elseif (!$this->floodIsAllowed($window)) {
      foreach ($this->tfaBasePlugin->getErrorMessages() as $message) {
        drupal_set_message($message, 'error');
      }
      return TRUE;
    }
    return FALSE;
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
