<?php

namespace Drupal\tfa\Form;

use Drupal\Component\Plugin\PluginManagerInterface;
use Drupal\Core\Form\FormBase;
use Drupal\Core\Form\FormStateInterface;
use Drupal\tfa\TfaDataTrait;
use Drupal\tfa\TfaSetup;
use Drupal\user\Entity\User;
use Drupal\user\UserDataInterface;
use Symfony\Component\DependencyInjection\ContainerInterface;

/**
 * TFA setup form router.
 */
class BasicSetup extends FormBase {
  use TfaDataTrait;

  /**
   * The TfaSetupPluginManager.
   *
   * @var \Drupal\Component\Plugin\PluginManagerInterface
   */
  protected $manager;

  /**
   * Provides the user data service object.
   *
   * @var \Drupal\user\UserDataInterface
   */
  protected $userData;

  /**
   * {@inheritdoc}
   */
  public static function create(ContainerInterface $container) {
    return new static(
      $container->get('plugin.manager.tfa.setup'),
      $container->get('user.data')
    );
  }

  /**
   * {@inheritdoc}
   */
  public function __construct(PluginManagerInterface $manager, UserDataInterface $user_data) {
    $this->manager = $manager;
    $this->userData = $user_data;
  }

  /**
   * {@inheritdoc}
   */
  public function getFormId() {
    return 'tfa_setup';
  }

  /**
   * {@inheritdoc}
   */
  public function buildForm(array $form, FormStateInterface $form_state, User $user = NULL, $method = 'tfa_totp', $reset = 0) {
    $account = User::load($this->currentUser()->id());

    $form['account'] = [
      '#type' => 'value',
      '#value' => $user,
    ];
    $tfa_data = $this->tfaGetTfaData($user->id(), $this->userData);
    $enabled = isset($tfa_data['status']) && $tfa_data['status'] ? TRUE : FALSE;

    $storage = $form_state->getStorage();
    // Always require a password on the first time through.
    if (empty($storage)) {
      // Allow administrators to change TFA settings for another account.
      if ($account->id() == $user->id() && $account->hasPermission('administer users')) {
        $current_pass_description = $this->t('Enter your current password to
        alter TFA settings for account %name.', ['%name' => $user->getUsername()]);
      }
      else {
        $current_pass_description = $this->t('Enter your current password to continue.');
      }

      $form['current_pass'] = [
        '#type' => 'password',
        '#title' => $this->t('Current password'),
        '#size' => 25,
        '#required' => TRUE,
        '#description' => $current_pass_description,
        '#attributes' => ['autocomplete' => 'off'],
      ];

      $form['submit'] = [
        '#type' => 'submit',
        '#value' => $this->t('Confirm'),
      ];

      $form['cancel'] = [
        '#type' => 'submit',
        '#value' => $this->t('Cancel'),
        '#limit_validation_errors' => [],
        '#submit' => ['::cancelForm'],
      ];
    }
    else {
      if (!$enabled && empty($storage['steps'])) {
        $storage['full_setup'] = TRUE;
        $steps = $this->tfaFullSetupSteps();
        $storage['steps_left'] = $steps;
        $storage['steps_skipped'] = [];
      }

      if (isset($storage['step_method'])) {
        $method = $storage['step_method'];
      }

      // Record methods progressed.
      $storage['steps'][] = $method;

      $plugin_id = $method . '_setup';
      $validation_inst = \Drupal::service('plugin.manager.tfa.setup');
      $setup_plugin = $validation_inst->createInstance($plugin_id, ['uid' => $account->id()]);
      $tfa_setup = new TfaSetup($setup_plugin);
      $form = $tfa_setup->getForm($form, $form_state, $reset);
      $storage[$method] = $tfa_setup;

      if (isset($storage['full_setup']) && count($storage['steps']) > 1) {
        $count = count($storage['steps_left']);
        $form['actions']['skip'] = [
          '#type' => 'submit',
          '#value' => $count > 0 ? $this->t('Skip') : $this->t('Skip and finish'),
          '#limit_validation_errors' => [],
          '#submit' => ['::cancelForm'],
        ];
      }
      // Provide cancel button on first step or single steps.
      else {
        $form['actions']['cancel'] = [
          '#type' => 'submit',
          '#value' => $this->t('Cancel'),
          '#limit_validation_errors' => [],
          '#submit' => ['::cancelForm'],
        ];
      }
      // Record the method in progress regardless of whether in full setup.
      $storage['step_method'] = $method;
    }
    $form_state->setStorage($storage);
    return $form;
  }

  /**
   * {@inheritdoc}
   */
  public function validateForm(array &$form, FormStateInterface $form_state) {
    $user = User::load($this->currentUser()->id());
    $storage = $form_state->getStorage();
    $values = $form_state->getValues();
    $account = $form['account']['#value'];
    if (isset($values['current_pass'])) {
      // Allow administrators to change TFA settings for another account.
      if ($account->id() != $user->id() && $user->hasPermission('administer users')) {
        $account = $user;
      }
      $current_pass = \Drupal::service('password')
        ->check(trim($form_state->getValue('current_pass')), $account->getPassword());
      if (!$current_pass) {
        $form_state->setErrorByName('current_pass', $this->t("Incorrect password."));
      }
      return;
    }
    elseif (!empty($storage['step_method'])) {
      $method = $storage['step_method'];
      $tfa_setup = $storage[$method];
      // Validate plugin form.
      if (!$tfa_setup->validateForm($form, $form_state)) {
        foreach ($tfa_setup->getErrorMessages() as $element => $message) {
          $form_state->setErrorByName($element, $message);
        }
      }
    }
  }

  /**
   * {@inheritdoc}
   */
  public function cancelForm(array &$form, FormStateInterface $form_state) {
    $account = $form['account']['#value'];
    drupal_set_message('TFA setup canceled.', 'warning');
    $form_state->setRedirect('tfa.overview', ['user' => $account->id()]);
  }

  /**
   * {@inheritdoc}
   */
  public function submitForm(array &$form, FormStateInterface $form_state) {
    $account = $form['account']['#value'];
    $storage = $form_state->getStorage();
    $values = $form_state->getValues();

    // Password validation.
    if (isset($values['current_pass'])) {
      $storage['pass_confirmed'] = TRUE;
      $form_state->setRebuild();
      $form_state->setStorage($storage);
      return;
    }
    elseif (!empty($storage['step_method'])) {
      $method = $storage['step_method'];
      $skipped_method = FALSE;

      // Support skipping optional steps when in full setup.
      if (isset($values['skip']) && $values['op'] === $values['skip']) {
        $skipped_method = $method;
        $storage['steps_skipped'][] = $method;
        unset($storage[$method]);
      }

      if (!empty($storage[$method])) {
        // Trigger multi-step if in full setup.
        if (!empty($storage['full_setup'])) {
          $this->tfaNextSetupStep($form_state, $method, $storage[$method], $skipped_method);
        }

        // Plugin form submit.
        $setup_class = $storage[$method];
        if (!$setup_class->submitForm($form, $form_state)) {
          drupal_set_message($this->t('There was an error during TFA setup. Your
          settings have not been saved.'), 'error');
          $form_state->setRedirect('tfa.overview', ['user' => $account->id()]);
          return;
        }
      }

      // Return if multi-step.
      if ($form_state->getRebuildInfo()) {
        return;
      }
      // Else, setup complete and return to overview page.
      drupal_set_message(t('TFA setup complete.'));
      $form_state->setRedirect('tfa.overview', ['user' => $account->id()]);

      // Log and notify if this was full setup.
      if (!empty($storage['step_method'])) {
        $data = ['plugins' => $storage['step_method']];
        $this->tfaSaveTfaData($account->id(), $this->userData, $data);
        \Drupal::logger('tfa')->info('TFA enabled for user @name UID @uid', [
          '@name' => $account->getUsername(),
          '@uid' => $account->id(),
        ]);

        // @todo Not working, not sure why though.
        // $params = array('account' => $account);
        // \Drupal::service('plugin.manager.mail')->mail('tfa_basic', 'tfa_basic_tfa_enabled', $account->getEmail(), $account->getPreferredLangcode(), $params);
      }
    }
  }

  /**
   * Steps eligble for TFA setup.
   */
  private function tfaFullSetupSteps() {
    $config = $this->config('tfa.settings');
    $enabled_plugin = $config->get('validation_plugin');
    $steps = [
      $config->get('validation_plugin'),
      key($config->get('fallback_plugins')[$enabled_plugin]),
    ];

    $login_plugins = $config->get('login_plugins');

    foreach ($login_plugins as $login_plugin) {
      $steps[] = $login_plugin;
    }

    // @todo Add send plugins.
    return $steps;
  }

  /**
   * Set form rebuild, next step, and message if any plugin steps left.
   *
   * @param \Drupal\Core\Form\FormStateInterface $form_state
   *   The current form state.
   * @param string $this_step
   *   The current setup step.
   * @param \Drupal\tfa\TfaSetup $step_class
   *   The setup instance of the current step.
   * @param bool $skipped_step
   *   Whether the step was skipped.
   */
  private function tfaNextSetupStep(FormStateInterface &$form_state, $this_step, TfaSetup $step_class, $skipped_step = FALSE) {
    $storage = $form_state->getStorage();
    // Remove this step from steps left.
    $storage['steps_left'] = array_diff($storage['steps_left'], [$this_step]);
    if (!empty($storage['steps_left'])) {
      // Contextual reporting.
      if ($output = $step_class->getSetupMessages()) {
        $output = $skipped_step ? $output['skipped'] : $output['saved'];
      }
      $count = count($storage['steps_left']);
      $output .= ' ' . \Drupal::translation()->formatPlural($count, 'One setup step remaining.', '@count TFA setup steps remain.', ['@count' => $count]);
      if ($output) {
        drupal_set_message($output);
      }

      // Set next step and mark form for rebuild.
      $next_step = array_shift($storage['steps_left']);
      $storage['step_method'] = $next_step;
      $form_state->setRebuild();
    }
    $form_state->setStorage($storage);
  }

}
