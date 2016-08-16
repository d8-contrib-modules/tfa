<?php

namespace Drupal\tfa\Form;

use Drupal\Component\Utility\Crypt;
use Drupal\Core\Flood\FloodInterface;
use Drupal\Core\Form\FormStateInterface;
use Drupal\Core\Render\RendererInterface;
use Drupal\Core\Url;
use Drupal\tfa\Plugin\TfaSendInterface;
use Drupal\tfa\Plugin\TfaValidationInterface;
use Drupal\tfa\TfaDataTrait;
use Drupal\tfa\TfaLoginPluginManager;
use Drupal\tfa\TfaValidationPluginManager;
use Drupal\user\Form\UserLoginForm;
use Drupal\user\UserAuthInterface;
use Drupal\user\UserDataInterface;
use Drupal\user\UserStorageInterface;
use Symfony\Component\DependencyInjection\ContainerInterface;

/**
 * TFA user login form.
 */
class TfaLoginForm extends UserLoginForm {
  use TfaDataTrait;

  /**
   * The validation plugin manager to fetch plugin information.
   *
   * @var \Drupal\tfa\TfaValidationPluginManager
   */
  protected $tfaValidationManager;

  /**
   * The login plugin manager to fetch plugin information.
   *
   * @var \Drupal\tfa\TfaLoginPluginManager
   */
  protected $tfaLoginManager;

  /**
   * The current validation plugin.
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
   * The user data service.
   *
   * @var \Drupal\user\UserDataInterface
   */
  protected $userData;

  /**
   * Constructs a new user login form.
   *
   * @param \Drupal\Core\Flood\FloodInterface $flood
   *   The flood service.
   * @param \Drupal\user\UserStorageInterface $user_storage
   *   The user storage.
   * @param \Drupal\user\UserAuthInterface $user_auth
   *   The user authentication object.
   * @param \Drupal\Core\Render\RendererInterface $renderer
   *   The renderer.
   * @param \Drupal\tfa\TfaValidationPluginManager $tfa_validation_manager
   *   Tfa validation plugin manager.
   * @param \Drupal\tfa\TfaLoginPluginManager $tfa_plugin_manager
   *   Tfa setup plugin manager.
   * @param \Drupal\user\UserDataInterface $user_data
   *   User data service.
   */
  public function __construct(FloodInterface $flood, UserStorageInterface $user_storage, UserAuthInterface $user_auth, RendererInterface $renderer, TfaValidationPluginManager $tfa_validation_manager, TfaLoginPluginManager $tfa_plugin_manager, UserDataInterface $user_data) {
    parent::__construct($flood, $user_storage, $user_auth, $renderer);
    $this->tfaValidationManager = $tfa_validation_manager;
    $this->tfaLoginManager = $tfa_plugin_manager;
    $this->userData = $user_data;
  }

  /**
   * {@inheritdoc}
   */
  public static function create(ContainerInterface $container) {
    return new static(
      $container->get('flood'),
      $container->get('entity.manager')->getStorage('user'),
      $container->get('user.auth'),
      $container->get('renderer'),
      $container->get('plugin.manager.tfa.validation'),
      $container->get('plugin.manager.tfa.login'),
      $container->get('user.data')
    );
  }

  /**
   * {@inheritdoc}
   */
  public function buildForm(array $form, FormStateInterface $form_state) {
    $form = parent::buildForm($form, $form_state);
    $form['#submit'][] = '::tfaLoginFormRedirect';

    return $form;
  }

  /**
   * Login submit handler.
   *
   * Determine if TFA process is applicable.If not, call the parent form submit.
   *
   * {@inheritdoc}
   */
  public function submitForm(array &$form, FormStateInterface $form_state) {
    // Similar to tfa_user_login() but not required to force user logout.
    $current_uid = $form_state->get('uid');
    $account = $this->userStorage->load($form_state->get('uid'));

    // Uncomment when things go wrong and you get logged out.
    // user_login_finalize($account);
    // $form_state->setRedirect('<front>');
    $tfa_enabled = intval($this->config('tfa.settings')->get('enabled'));
    $allowed_skips = intval($this->config('tfa.settings')->get('validation_skip'));

    // GetPlugin
    // Pass to service functions.
    $validation_plugin = $this->config('tfa.settings')->get('validation_plugin');
    $tfaValidationPlugin = $this->tfaValidationManager->createInstance($validation_plugin, ['uid' => $account->id()]);
    $this->tfaLoginPlugins = $this->tfaLoginManager->getPlugins(['uid' => $account->id()]);

    // Setup TFA.
    if (isset($tfaValidationPlugin) && $tfa_enabled && $account->hasPermission('require tfa')) {
      if ($this->ready($tfaValidationPlugin) && $this->loginAllowed()) {
        user_login_finalize($account);
        drupal_set_message('You have logged in on a trusted browser.');
        $form_state->setRedirect('<front>');
      }
      elseif (!$this->ready($tfaValidationPlugin)) {
        $tfa_data = $this->tfaGetTfaData($account->id(), $this->userData);
        $validation_skipped = (isset($tfa_data['validation_skipped'])) ? $tfa_data['validation_skipped'] : 0;
        if ($allowed_skips && ($left = $allowed_skips - ++$validation_skipped) >= 0) {
          $tfa_data['validation_skipped'] = $validation_skipped;

          $tfa_setup_link = Url::fromRoute('tfa.overview', array(
            'user' => $account->id(),
          ));
          $tfa_setup_link = $tfa_setup_link->toString();
          drupal_set_message($this->t('You are required to setup two-factor
          authentication <a href="@link">here.</a> You have @skipped attempts
          left after this you will be unable to login.', [
            '@skipped' => $left,
            '@link' => $tfa_setup_link,
          ]), 'error');
          $this->tfaSaveTfaData($account->id(), $this->userData, $tfa_data);
          user_login_finalize($account);
          $form_state->setRedirect('<front>');
        }
      }
      elseif ($this->ready($tfaValidationPlugin) && !$this->loginAllowed($account)) {

        // Restart flood levels, session context, and TFA process.
        // flood_clear_event('tfa_validate');
        // flood_register_event('tfa_begin');
        // $query = drupal_get_query_parameters();

        // Begin TFA and set process context.
        // @todo This is used in send plugins which has not been implemented
        // yet.
        // $this->begin($tfaValidationPlugin);
        $login_hash = $this->getLoginHash($account);
        $form_state->setRedirect(
          'tfa.entry',
          [
            'user' => $account->id(),
            'hash' => $login_hash,
          ]
        );
      }
      else {
        drupal_set_message($this->t('Two-factor authentication is enabled but
        misconfigured. Please contact a site administrator.'), 'error');
        $form_state->setRedirect('user.page');
      }
    }
    else {
      return parent::submitForm($form, $form_state);
    }
  }

  /**
   * Login submit handler for TFA form redirection.
   *
   * Should be last invoked form submit handler for forms user_login and
   * user_login_block so that when the TFA process is applied the user will be
   * sent to the TFA form.
   *
   * @param FormStateInterface $form_state
   *   The current form state.
   */
  public function tfaLoginFormRedirect($form, FormStateInterface $form_state) {
    $route = $form_state->getValue('tfa_redirect');
    if (isset($route)) {
      $form_state->setRedirect($route);
    }
  }

  /**
   * Determine if TFA process is ready.
   *
   * @param \Drupal\tfa\Plugin\TfaValidationInterface $tfaValidationPlugin
   *   The plugin instance of the validation method.
   *
   * @return bool
   *   Whether process can begin or not.
   */
  protected function ready(TfaValidationInterface $tfaValidationPlugin) {
    return $tfaValidationPlugin->ready();
  }

  /**
   * Whether authentication should be allowed and not interrupted.
   *
   * If any plugin returns TRUE then authentication is not interrupted by TFA.
   *
   * @return bool
   *   TRUE if login allowed otherwise FALSE.
   */
  protected function loginAllowed() {
    if (!empty($this->tfaLoginPlugins)) {
      foreach ($this->tfaLoginPlugins as $plugin) {
        if ($plugin->loginAllowed()) {
          return TRUE;
        }
      }
    }
    return FALSE;
  }

  /**
   * Begin the TFA process.
   *
   * @param \Drupal\tfa\Plugin\TfaSendInterface $tfaSendPlugin
   *   The send plugin instance.
   */
  protected function begin(TfaSendInterface $tfaSendPlugin) {
    // Invoke begin method on send validation plugins.
    if (method_exists($tfaSendPlugin, 'begin')) {
      $tfaSendPlugin->begin();
    }
  }

  /**
   * Generate account hash to access the TFA form.
   *
   * @param object $account User account.
   *
   * @return string Random hash.
   */

  /**
   * Function tfa_login_hash($account) {.
   */
  protected function getLoginHash($account) {
    // Using account login will mean this hash will become invalid once user has
    // authenticated via TFA.
    $data = implode(':', [
      $account->getUsername(),
      $account->getPassword(),
      $account->getLastLoginTime(),
    ]);
    return Crypt::hashBase64($data);
  }

}
