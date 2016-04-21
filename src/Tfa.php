<?php

/**
 * @file TFA module classes
 * Contains \Drupal\tfa\Tfa.
 */

namespace Drupal\tfa;

use Drupal\Component\Utility\SafeMarkup;
use Drupal\tfa\Plugin\TfaBasePlugin;
use Drupal\Core\Form\FormStateInterface;

/**
 * Class Tfa
 *
 * Defines a TFA object.
 *
 */
class Tfa {

  /**
   * @var array
   */
  protected $context;

  /**
   * @var TfaBasePlugin
   */
  protected $validatePlugin;

  /**
   * @var array
   */
  protected $loginPlugins = array();

  /**
   * @var array
   */
  protected $fallbackPlugins = array();

  /**
   * @var bool
   */
  protected $complete = FALSE;

  /**
   * @var bool
   */
  protected $fallback = FALSE;

  /**
   * TFA constructor.
   *
   * @param array $plugins
   *   Plugins to instansiate.
   *
   *   Must include key:
   *
   *     - 'validate'
   *       Class name of TfaBasePlugin implementing TfaValidationPluginInterface.
   *
   *   May include keys:
   *
   *     - 'login'
   *       Array of classes of TfaBasePlugin implementing TfaLoginPluginInterface.
   *
   *     - 'fallback'
   *       Array of classes of TfaBasePlugin that can be used as fallback processes.
   *
   * @param array $context
   *   Context of TFA process.
   *
   *   Must include key:
   *
   *     - 'uid'
   *       Account uid of user in TFA process.
   *
   */
  public function __construct(array $plugins, array $context) {
    if (empty($plugins)) {
      throw new \RuntimeException(
        SafeMarkup::format('TFA must have at least 1 valid plugin',
          array('@function' => 'Tfa::__construct')));
    }
    if (empty($plugins['validate'])) {
      throw new \RuntimeException(
        SafeMarkup::format('TFA must have at least 1 valid validation plugin',
          array('@function' => 'Tfa::__construct')));
    }

    //Load up the current validation plugin.
    $validation_service = \Drupal::service('plugin.manager.tfa.validation');
    $validate_plugin = $validation_service->getDefinition($plugins['validate']);
    $this->validatePlugin = new $validate_plugin['class']($context);

    //Check for login plugins (Shou'd this really be a loop?)
    if (!empty($plugins['login'])) {
      foreach ($plugins['login'] as $class) {
        $this->loginPlugins[] = new $class($context);
      }
    }
    //Check for fallback plugins
    if (!empty($plugins['fallback'])) {
      $plugins['fallback'] = array_unique($plugins['fallback']);
      // @todo consider making plugin->ready a class method?
      foreach ($plugins['fallback'] as $key => $class) {
        if ($class === $plugins['validate']) {
          unset($plugins['fallback'][$key]);
          continue; // Skip this fallback if its same as validation.
        }
        $fallback = new $class($context);
        // Only plugins that are ready can stay.
        if ($fallback->ready()) {
          $this->fallbackPlugins[] = $class;
        }
        else {
          unset($plugins['fallback'][$key]);
        }
      }
      if (!empty($this->fallbackPlugins)) {
        $this->fallback = TRUE;
      }
    }
    $this->context = $context;
    $this->context['plugins'] = $plugins;
  }




  /**
   * Get TFA process form from plugin.
   *
   * @param array $form
   * @param FormStateInterface $form_state
   * @return array Form API array.
   * @deprecated
   */
  public function getForm(array $form, FormStateInterface $form_state) {
    $form = $this->validatePlugin->getForm($form, $form_state);
    // Allow login plugins to modify form.
    if (!empty($this->loginPlugins)) {
      foreach ($this->loginPlugins as $class) {
        if (method_exists($class, 'getForm')) {
          $form = $class->getForm($form, $form_state);
        }
      }
    }
    return $form;
  }

  /**
   * Return process error messages.
   *
   * @return array
   * @deprecated
   */
  public function getErrorMessages() {
    return $this->validatePlugin->getErrorMessages();
  }

  /**
   * Invoke submitForm() on plugins.
   *
   * - Check Fallback to see if it was triggered.
   * - If no Fallback was called, call current plugin's submitForm().
   *
   * @param array $form
   * @param FormStateInterface $form_state
   * @return bool Whether the validate plugin is complete.
   *   FALSE will cause tfa_form_submit() to rebuild the form for multi-step.
   * @deprecated
   */
  public function submitForm(array $form, FormStateInterface $form_state) {
    // Handle fallback if set.
    $fallback = $form_state->getValue('fallback');
    if ($this->fallback && isset($fallback) && $form_state->getValue('op') === $fallback) {
      // Change context to next fallback and reset validatePlugin.
      $this->context['plugins']['validate'] = array_shift($this->context['plugins']['fallback']);
      $class = $this->context['plugins']['validate'];
      $this->validatePlugin = new $class($this->context);
      if (empty($this->context['plugins']['fallback'])) {
        $this->fallback = FALSE;
      }
      // Record which plugin is activated as fallback.
      $this->context['active_fallback'] = $this->context['plugins']['validate'];
    }
    // Otherwise invoke plugin submitForm().
    elseif (method_exists($this->validatePlugin, 'submitForm')) {
      // Check if plugin is complete.
      $this->complete = $this->validatePlugin->submitForm($form, $form_state);
    }
    // Allow login plugins to handle form submit.
    if (!empty($this->loginPlugins)) {
      foreach ($this->loginPlugins as $class) {
        if (method_exists($class, 'submitForm')) {
          $class->submitForm($form, $form_state);
        }
      }
    }
    return $this->complete;
  }


  /**
   * Whether the TFA process has any fallback proceses.
   *
   * @return bool
   * @deprecated
   */
  public function hasFallback() {
    return $this->fallback;
  }

  /**
   * Return TFA context.
   *
   * @return array
   * @deprecated
   */
  public function getContext() {
    if (method_exists($this->validatePlugin, 'getPluginContext')) {
      $pluginContext = $this->validatePlugin->getPluginContext();
      $this->context['validate_context'] = $pluginContext;
    }
    return $this->context;
  }

  /**
   * Run TFA process finalization.
   * @deprecated
   */
  public function finalize() {
    // Invoke plugin finalize.
    if (method_exists($this->validatePlugin, 'finalize')) {
      $this->validatePlugin->finalize();
    }
    // Allow login plugins to act during finalization.
    if (!empty($this->loginPlugins)) {
      foreach ($this->loginPlugins as $class) {
        if (method_exists($class, 'finalize')) {
          $class->finalize();
        }
      }
    }
  }

}
