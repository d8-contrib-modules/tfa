<?php

namespace Drupal\tfa\Form;

use Drupal\Core\Config\ConfigFactoryInterface;
use Drupal\Core\Form\ConfigFormBase;
use Drupal\Core\Form\FormStateInterface;
use Drupal\tfa\TfaDataTrait;
use Drupal\tfa\TfaLoginPluginManager;
use Drupal\tfa\TfaSendPluginManager;
use Drupal\tfa\TfaSetupPluginManager;
use Drupal\tfa\TfaValidationPluginManager;
use Drupal\user\UserDataInterface;
use Symfony\Component\DependencyInjection\ContainerInterface;

/**
 * The admin configuration page.
 */
class SettingsForm extends ConfigFormBase {
  use TfaDataTrait;

  /**
   * The login plugin manager to fetch plugin information.
   *
   * @var \Drupal\tfa\TfaLoginPluginManager
   */
  protected $tfaLogin;

  /**
   * The send plugin manager to fetch plugin information.
   *
   * @var \Drupal\tfa\TfaSendPluginManager
   */
  protected $tfaSend;

  /**
   * The validation plugin manager to fetch plugin information.
   *
   * @var \Drupal\tfa\TfaValidationPluginManager
   */
  protected $tfaValidation;

  /**
   * The setup plugin manager to fetch plugin information.
   *
   * @var \Drupal\tfa\TfaSetupPluginManager
   */
  protected $tfaSetup;

  /**
   * Provides the user data service object.
   *
   * @var \Drupal\user\UserDataInterface
   */
  protected $userData;

  /**
   * The admin configuraiton form constructor.
   *
   * @param \Drupal\Core\Config\ConfigFactoryInterface $config_factory
   *   The config factory object.
   * @param \Drupal\tfa\TfaLoginPluginManager $tfa_login
   *   The login plugin manager.
   * @param \Drupal\tfa\TfaSendPluginManager $tfa_send
   *   The send plugin manager.
   * @param \Drupal\tfa\TfaValidationPluginManager $tfa_validation
   *   The validation plugin manager.
   * @param \Drupal\tfa\TfaSetupPluginManager $tfa_setup
   *   The setup plugin manager.
   * @param \Drupal\user\UserDataInterface $user_data
   *   The user data service.
   */
  public function __construct(ConfigFactoryInterface $config_factory, TfaLoginPluginManager $tfa_login, TfaSendPluginManager $tfa_send, TfaValidationPluginManager $tfa_validation, TfaSetupPluginManager $tfa_setup, UserDataInterface $user_data) {
    parent::__construct($config_factory);
    $this->tfaLogin      = $tfa_login;
    $this->tfaSend       = $tfa_send;
    $this->tfaSetup      = $tfa_setup;
    $this->tfaValidation = $tfa_validation;

    // User Data service to store user-based data in key value pairs.
    $this->userData = $user_data;
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
      $container->get('config.factory'),
      $container->get('plugin.manager.tfa.login'),
      $container->get('plugin.manager.tfa.send'),
      $container->get('plugin.manager.tfa.validation'),
      $container->get('plugin.manager.tfa.setup'),
      $container->get('user.data')
    );
  }

  /**
   * {@inheritdoc}
   */
  public function getFormId() {
    return 'tfa_settings_form';
  }

  /**
   * {@inheritdoc}
   */
  public function buildForm(array $form, FormStateInterface $form_state) {
    $config = $this->config('tfa.settings');
    $form   = array();

    // TODO - Wondering if all modules extend TfaBasePlugin
    // Get Login Plugins.
    $login_plugins = $this->tfaLogin->getDefinitions();

    // Get Send Plugins.
    $send_plugins = $this->tfaSend->getDefinitions();

    // Get Validation Plugins.
    $validate_plugins = $this->tfaValidation->getDefinitions();

    // Get validation plugin labels and their fallbacks.
    $validate_plugins_labels    = [];
    $validate_plugins_fallbacks = [];
    foreach ($validate_plugins as $plugin) {
      $validate_plugins_labels[$plugin['id']] = $plugin['label']->render();
      if (isset($plugin['fallbacks'])) {
        $validate_plugins_fallbacks[$plugin['id']] = $plugin['fallbacks'];
      }
    }

    // Get Setup Plugins.
    $setup_plugins = $this->tfaSetup->getDefinitions();

    // Check if mcrypt plugin is available.
    /*
    if (!extension_loaded('mcrypt')) {
    // @todo allow alter in case of other encryption libs.
    drupal_set_message(t('The TFA module requires the PHP Mcrypt extension be installed on the web server. See <a href="!link">the TFA help documentation</a> for setup.', array('!link' => \Drupal\Core\Url::fromRoute('help.page'))), 'error');

    return parent::buildForm($form, $form_state);;
    }
     */

    // Return if there are no plugins.
    // TODO - Why check for plugins here?
    // if (empty($plugins) || empty($validate_plugins)) {.
    if (empty($validate_plugins)) {
      // drupal_set_message(t('No plugins available for validation. See <a href="!link">the TFA help documentation</a> for setup.', array('!link' => \Drupal\Core\Url::fromRoute('help.page'))), 'error');.
      drupal_set_message(t('No plugins available for validation. See the TFA help documentation for setup.'), 'error');
      return parent::buildForm($form, $form_state);
    }

    // Option to enable entire process or not.
    $form['tfa_enabled'] = array(
      '#type'          => 'checkbox',
      '#title'         => t('Enable TFA'),
      '#default_value' => $config->get('enabled'),
      '#description'   => t('Enable TFA for account authentication.'),
    );

    $enabled_state = array(
      'visible' => array(
        ':input[name="tfa_enabled"]' => array('checked' => TRUE),
      ),
    );

    if (count($validate_plugins)) {
      $form['tfa_validate'] = array(
        '#type'          => 'select',
        '#title'         => t('Default validation plugin'),
        '#options'       => $validate_plugins_labels,
        '#default_value' => \Drupal::config('tfa.settings')->get('validate_plugin'),
        '#description'   => t('Plugin that will be used as the default TFA process.'),
        // Show only when TFA is enabled.
        '#states'        => $enabled_state,
      );
    }
    else {
      $form['no_validate'] = array(
        '#value'  => 'markup',
        '#markup' => t('No available validation plugins available. TFA process will not occur.'),
      );
    }

    if (count($validate_plugins_fallbacks)) {
      $form['tfa_fallback'] = array(
        '#type'        => 'fieldset',
        '#title'       => t('Validation fallback plugins'),
        '#description' => t('Fallback plugins and order. Note, if a fallback plugin is not setup for an account it will not be active in the TFA form.'),
        '#states'      => $enabled_state,
        '#tree'        => TRUE,
      );

      $enabled_fallback_plugins = \Drupal::config('tfa.settings')->get('fallback_plugins');
      foreach ($validate_plugins_fallbacks as $plugin => $fallbacks) {
        $fallback_state = array(
          'visible' => array(
            ':input[name="tfa_validate"]' => array('value' => $plugin),
          ),
        );
        if (count($fallbacks)) {
          foreach ($fallbacks as $fallback) {
            $order                                    = (@$enabled_fallback_plugins[$plugin][$fallback]['weight']) ?: -2;
            $fallback_value                           = (@$enabled_fallback_plugins[$plugin][$fallback]['enable']) ?: 1;
            $form['tfa_fallback'][$plugin][$fallback] = array(
              'enable' => array(
                '#title'         => $validate_plugins_labels[$fallback],
                '#type'          => 'checkbox',
                '#default_value' => $fallback_value,
                '#states'        => $fallback_state,
              ),
              'weight' => array(
                '#type'          => 'weight',
                '#title'         => t('Order'),
                '#delta'         => 2,
                '#default_value' => $order,
                '#title_display' => 'invisible',
                '#states'        => $fallback_state,
              ),
            );
          }
        }
        else {
          $form['tfa_fallback'][$plugin] = array(
            '#type'        => 'item',
            '#description' => t('No fallback plugins available.'),
            '#states'      => $fallback_state,
          );
        }
      }
    }

    $form['validation_skip'] = [
      '#type' => 'textfield',
      '#title' => t('Skip Validation'),
      '#default_value' => ($config->get('validation_skip')) ?: 2,
      '#description' => 'No. of times a user without having setup tfa validation can login.',
      '#size' => 2,
      '#states' => $enabled_state,
    ];

    // Enable login plugins.
    if (count($login_plugins)) {
      $login_form_array = array();

      foreach ($login_plugins as $login_plugin) {
        $id                    = $login_plugin['id'];
        $title                 = $login_plugin['label']->render();
        $login_form_array[$id] = (string) $title;
      }

      $form['tfa_login'] = array(
        '#type'          => 'checkboxes',
        '#title'         => t('Login plugins'),
        '#options'       => $login_form_array,
        '#default_value' => ($config->get('login_plugins')) ? $config->get('login_plugins') : array(),
        '#description'   => t('Plugins that can allow a user to skip the TFA process. If any plugin returns true the user will not be required to follow TFA. <strong>Use with caution.</strong>'),
      );
    }

    // Enable send plugins.
    if (count($send_plugins)) {
      $send_form_array = array();

      foreach ($send_plugins as $send_plugin) {
        $id                   = $send_plugin['id'];
        $title                = $send_plugin['label']->render();
        $send_form_array[$id] = (string) $title;
      }

      $form['tfa_send'] = array(
        '#type'          => 'checkboxes',
        '#title'         => t('Send plugins'),
        '#options'       => $send_form_array,
        '#default_value' => ($config->get('send_plugins')) ? $config->get('send_plugins') : array(),
        // TODO - Fill in description.
        '#description'   => t('Not sure what this is'),
      );
    }

    // Enable setup plugins.
    if (count($setup_plugins) >= 1) {
      $setup_form_array = array();

      foreach ($setup_plugins as $setup_plugin) {
        $id                    = $setup_plugin['id'];
        $title                 = $setup_plugin['label']->render();
        $setup_form_array[$id] = $title;
      }

      $form['tfa_setup'] = array(
        '#type'          => 'checkboxes',
        '#title'         => t('Setup plugins'),
        '#options'       => $setup_form_array,
        '#default_value' => ($config->get('setup_plugins')) ? $config->get('setup_plugins') : array(),
        // TODO - Fill in description.
        '#description'   => t('Not sure what this is'),
      );
    }

    return parent::buildForm($form, $form_state);
  }

  /**
   * {@inheritdoc}
   */
  public function validateForm(array &$form, FormStateInterface $form_state) {
    return parent::validateForm($form, $form_state);
  }

  /**
   * {@inheritdoc}
   */
  public function submitForm(array &$form, FormStateInterface $form_state) {
    $validate_plugin  = $form_state->getValue('tfa_validate');
    $fallback_plugins = $form_state->getValue('tfa_fallback');

    // Delete tfa data if plugin is disabled.
    if ($this->config('tfa.settings')->get('enabled') && !$form_state->getValue('tfa_enabled')) {
      $this->userData->delete('tfa');
    }

    $setup_plugins = $form_state->getValue('tfa_setup') ?: [];
    $send_plugins = $form_state->getValue('tfa_send') ?: [];
    $login_plugins = $form_state->getValue('tfa_login') ?: [];
    $this->config('tfa.settings')
         ->set('enabled', $form_state->getValue('tfa_enabled'))
         ->set('setup_plugins', array_filter($setup_plugins))
         ->set('send_plugins', array_filter($send_plugins))
         ->set('login_plugins', array_filter($login_plugins))
         ->set('validate_plugin', $validate_plugin)
         ->set('fallback_plugins', $fallback_plugins)
         ->set('validation_skip', $form_state->getValue('validation_skip'))
         ->save();

    parent::submitForm($form, $form_state);
  }

  /**
   * {@inheritdoc}
   */
  protected function getEditableConfigNames() {
    return ['tfa.settings'];
  }

}
