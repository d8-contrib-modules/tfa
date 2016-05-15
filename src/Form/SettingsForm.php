<?php

/**
 * @file
 * Contains Drupal\tfa\Form\SettingsForm.
 */

namespace Drupal\tfa\Form;

use Drupal\Core\Config\ConfigFactoryInterface;
use Drupal\Core\Form\ConfigFormBase;
use Drupal\Core\Form\FormStateInterface;
use Drupal\tfa\TfaLoginPluginManager;
use Drupal\tfa\TfaSendPluginManager;
use Drupal\tfa\TfaSetupPluginManager;
use Drupal\tfa\TfaValidationPluginManager;
use Symfony\Component\DependencyInjection\ContainerInterface;

class SettingsForm extends ConfigFormBase {


  /**
   * @var
   */
  protected $configFactory;

  /**
   * @var \Drupal\tfa\TfaLoginPluginManager
   */
  protected $tfaLogin;
  /**
   * @var \Drupal\tfa\TfaSendPluginManager
   */
  protected $tfaSend;
  /**
   * @var \Drupal\tfa\TfaValidationPluginManager
   */
  protected $tfaValidation;
  /**
   * @var \Drupal\tfa\TfaSetupPluginManager
   */
  protected $tfaSetup;

  public function __construct(ConfigFactoryInterface $config_factory, TfaLoginPluginManager $tfa_login, TfaSendPluginManager $tfa_send, TfaValidationPluginManager $tfa_validation, TfaSetupPluginManager $tfa_setup) {
    parent::__construct($config_factory);
    $this->tfaLogin = $tfa_login;
    $this->tfaSend = $tfa_send;
    $this->tfaSetup = $tfa_setup;
    $this->tfaValidation = $tfa_validation;
  }


  public static function create(ContainerInterface $container){
    return new static(
      $container->get('config.factory'),
      $container->get('plugin.manager.tfa.login'),
      $container->get('plugin.manager.tfa.send'),
      $container->get('plugin.manager.tfa.validation'),
      $container->get('plugin.manager.tfa.setup')
    );
  }


  /**
   * {@inheritdoc}
   */
  public function getFormID() {
    return 'tfa_settings_form';
  }

  /**
   * {@inheritdoc}
   */
  public function buildForm(array $form, FormStateInterface $form_state) {
    $config = $this->config('tfa.settings');
    $form = array();

    //TODO - Wondering if all modules extend TfaBasePlugin
    //Get Login Plugins
    $login_plugins = $this->tfaLogin->getDefinitions();

    //Get Send Plugins
    $send_plugins = $this->tfaSend->getDefinitions();

    //Get Validation Plugins
    $validate_plugins = $this->tfaValidation->getDefinitions();

    //Get Setup Plugins
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
    //TODO - Why check for plugins here?
    //if (empty($plugins) || empty($validate_plugins)) {
    if (empty($validate_plugins)) {
      //drupal_set_message(t('No plugins available for validation. See <a href="!link">the TFA help documentation</a> for setup.', array('!link' => \Drupal\Core\Url::fromRoute('help.page'))), 'error');
      drupal_set_message(t('No plugins available for validation. See the TFA help documentation for setup.'), 'error');
      return parent::buildForm($form, $form_state);
    }

    // Option to enable entire process or not.
    $form['tfa_enabled'] = array(
      '#type' => 'checkbox',
      '#title' => t('Enable TFA'),
      '#default_value' => $config->get('enabled'),
      '#description' => t('Enable TFA for account authentication.'),
    );
    
	// Option to set tfa tab in userprofile
	$form['weight'] = array(
     '#type' => 'weight',
     '#title' => $this->t('Weight of the tfa tab'),
     '#default_value' => $config->get('weight'),
     '#delta' => 30,
    );

    //@TODO Figure out why we allow multiple validation plugins?
    if (count($validate_plugins)) {

      //order plugins by weight
      $weights = ($config->get('validate_weights')) ? $config->get('validate_weights') : array();

      //sort weight array by weight
      asort($weights);
      //get the max weight for unregistered elements
      $max_weight = max(array_values($weights));

      $form['validate_plugins'] = array(
        '#type' => 'table',
        '#header' => array(t('Enabled'), t('Validation Plugins'), t('Weight'),),
        '#empty' => t('There are no constraints for the selected user roles'),
        //TODO - This is throwing errors due to combination of weighting and checkboxes
        //'#tableselect' => TRUE,
        '#tabledrag' => array(
          array(
            'action' => 'order',
            'relationship' => 'sibling',
            'group' => 'validate-plugins-order-weight',
          ),
        ),
        //'#default_value' => ($config->get('validate_plugins'))?$config->get('validate_plugins'):array(),
      );

      //add unregistered plugins to weighted array
      foreach ($validate_plugins as $validate_plugin) {
        $id = $validate_plugin['id'];
        if (!in_array($id, array_keys($weights))) {
          $max_weight++;
          $weights[$id] = $max_weight;
        }
      }

      // Render table.
      foreach ($weights as $id => $weight) {
        // @todo: Plugin removed but stored in $weights - whops.
        if (!isset($validate_plugins[$id])) {
          continue;
        }
        $validate_plugin = $validate_plugins[$id];
        $title = $validate_plugin['label']->render();
        // TableDrag: Mark the table row as draggable.
        $form['validate_plugins'][$id]['#attributes']['class'][] = 'draggable';
        // TableDrag: Sort the table row according to its existing/configured weight.
        $form['validate_plugins'][$id]['#weight'] = $weight;

        // Some table columns containing raw markup.
        $form['validate_plugins'][$id]['enabled'] = array(
          '#type' => 'checkbox',
          '#return_value' => $id,
          '#default_value' => (in_array($id, $config->get('validate_plugins')) ? $id : '0')
        );

        $form['validate_plugins'][$id]['title'] = array(
          '#markup' => $title . ' (' . $validate_plugin['provider'] . ')',
        );

        // TableDrag: Weight column element.
        $form['validate_plugins'][$id]['weight'] = array(
          '#type' => 'weight',
          '#title' => t('Weight for @title', array('@title' => $title)),
          '#title_display' => 'invisible',
          '#default_value' => $weight,
          // Classify the weight element for #tabledrag.
          '#attributes' => array('class' => array('validate-plugins-order-weight')),
        );
      }


    }
    else {
      $form['no_validate'] = array(
        '#value' => 'markup',
        '#markup' => t('No available validation plugins available. TFA process will not occur.'),
      );
    }


    // Enable login plugins.
    if (count($login_plugins)) {
      $login_form_array = array();

      foreach ($login_plugins as $login_plugin) {
        $id = $login_plugin['id'];
        $title = $login_plugin['label']->render();
        $login_form_array[$id] = (string) $title;
      }

      $form['tfa_login'] = array(
        '#type' => 'checkboxes',
        '#title' => t('Login plugins'),
        '#options' => $login_form_array,
        '#default_value' => ($config->get('login_plugins')) ? $config->get('login_plugins') : array(),
        '#description' => t('Plugins that can allow a user to skip the TFA process. If any plugin returns true the user will not be required to follow TFA. <strong>Use with caution.</strong>'),
      );
    }

    // Enable send plugins.
    if (count($send_plugins)) {
      $send_form_array = array();

      foreach ($send_plugins as $send_plugin) {
        $id = $send_plugin['id'];
        $title = $send_plugin['label']->render();
        $send_form_array[$id] = (string) $title;
      }

      $form['tfa_send'] = array(
        '#type' => 'checkboxes',
        '#title' => t('Send plugins'),
        '#options' => $send_form_array,
        '#default_value' => ($config->get('send_plugins')) ? $config->get('send_plugins') : array(),
        //TODO - Fill in description
        '#description' => t('Not sure what this is'),
      );
    }

    // Enable setup plugins.
    if (count($setup_plugins) >= 1) {
      $setup_form_array = array();

      foreach ($setup_plugins as $setup_plugin) {
        $id = $setup_plugin['id'];
        $title = $setup_plugin['label']->render();
        $setup_form_array[$id] = $title;
      }

      $form['tfa_setup'] = array(
        '#type' => 'checkboxes',
        '#title' => t('Setup plugins'),
        '#options' => $setup_form_array,
        '#default_value' => ($config->get('setup_plugins')) ? $config->get('setup_plugins') : array(),
        //TODO - Fill in description
        '#description' => t('Not sure what this is'),
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
    $validate_plugins = array();
    $validate_weights = array();

    $validate_values = $form_state->getValue('validate_plugins');

    foreach ($validate_values as $plugin_id => $plugin_settings) {
      if ($plugin_settings['enabled']) {
        $validate_plugins[$plugin_id] = $plugin_id;
      }

      $validate_weights[$plugin_id] = $plugin_settings['weight'];
    }

    $this->config('tfa.settings')
      ->set('enabled', $form_state->getValue('tfa_enabled'))
	  ->set('weight', $form_state->getValue('weight'))
      ->set('setup_plugins', array_filter($form_state->getValue('tfa_setup')))
      ->set('send_plugins', array_filter($form_state->getValue('tfa_send')))
      ->set('login_plugins', array_filter($form_state->getValue('tfa_login')))
      ->set('validate_plugins', $validate_plugins)
      ->set('validate_weights', $validate_weights)
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
