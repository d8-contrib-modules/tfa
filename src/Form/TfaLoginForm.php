<?php
/**
 * @file TfaLoginForm.php
 * Contains implementation of the TfaLoginForm class.
 */

namespace Drupal\tfa\Form;

use Drupal\tfa\TfaValidationPluginManager;
use Drupal\user\Form\UserLoginForm;
use Drupal\Core\Flood\FloodInterface;
use Drupal\Core\Form\FormStateInterface;
use Drupal\Core\Render\RendererInterface;
use Drupal\user\UserAuthInterface;
use Drupal\user\UserStorageInterface;
use Symfony\Component\DependencyInjection\ContainerInterface;
use Drupal\tfa\Plugin\TfaValidationInterface;
use Drupal\tfa\Plugin\TfaLoginInterface;
use Drupal\Component\Utility\Crypt;

class TfaLoginForm extends UserLoginForm {

  /**
   * @var \Drupal\tfa\TfaValidationPluginManager
   */
  protected $tfaValidationManager;

  /**
   * Constructs a new UserLoginForm.
   *
   * @param \Drupal\Core\Flood\FloodInterface $flood
   *   The flood service.
   * @param \Drupal\user\UserStorageInterface $user_storage
   *   The user storage.
   * @param \Drupal\user\UserAuthInterface $user_auth
   *   The user authentication object.
   * @param \Drupal\Core\Render\RendererInterface $renderer
   *   The renderer.
   */
  public function __construct(FloodInterface $flood, UserStorageInterface $user_storage, UserAuthInterface $user_auth, RendererInterface $renderer, TfaValidationPluginManager $tfa_validation_manager) {
    parent::__construct($flood, $user_storage, $user_auth, $renderer);
    $this->tfaValidationManager = $tfa_validation_manager;
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
      $container->get('plugin.manager.tfa.validation')
    );
  }

  /**
   * {@inheritdoc}
   */
  public function buildForm(array $form, FormStateInterface $form_state) {
    $form = parent::buildForm($form, $form_state);
    $form['#submit'][] = '::TfaLoginFormRedirect';

    return $form;
  }

  /**
   * Login submit handler to determine if TFA process is applicable. If not,
   * call the parent form submit.
   *
   * {@inheritdoc}
   */
  public function submitForm(array &$form, FormStateInterface $form_state) {
    // Similar to tfa_user_login() but not required to force user logout.
    /** @var $account \Drupal\user\UserInterface */
    $account = $this->userStorage->load($form_state->get('uid'));


    //GetPlugin
    //Pass to service functions.
    /** @var  $tfaValidationPlugin \Drupal\tfa\Plugin\TfaValidationInterface */
    $tfaValidationPlugin = $this->tfaValidationManager->getInstance(['uid' => $account->id()]);

    //Setup TFA
    if (isset($tfaValidationPlugin)) {
      if ($account->hasPermission('require tfa') && !$this->loginComplete($account) && !$this->ready($tfaValidationPlugin)) {
        drupal_set_message(t('Login disallowed. You are required to setup two-factor authentication. Please contact a site administrator.'), 'error');
        $form_state->setRedirect('user.page');
      }
      elseif (!$this->loginComplete($account) && $this->ready($tfaValidationPlugin)) {  // && !$this->loginAllowed($account)) {

        // Restart flood levels, session context, and TFA process.
        //flood_clear_event('tfa_validate');
        //flood_register_event('tfa_begin');
//      $context = tfa_start_context($account);
//      $tfa = _tfa_get_process($account);

        // $query = drupal_get_query_parameters();
        if (!empty($form_state->redirect)) {
          // If there's an existing redirect set it in TFA context and
          // tfa_form_submit() will extract and set once process is complete.
          $context['redirect'] = $form_state->redirect;
        }

        // Begin TFA and set process context.
        $this->begin($tfaValidationPlugin);
        //$context = $tfa->getContext();
        //$this->tfaManager->setContext($account, $context);

        $login_hash = $this->getLoginHash($account);
        $form_state->setRedirect(
          'tfa.entry',
          ['user' => $account->id(),
            'hash' => $login_hash]
        //'tfa/' . $account->id() . '/' . $login_hash
        //array('query' => $query),
        );
      }
      else {
        return parent::submitForm($form, $form_state);
      }
    }
    else {
      drupal_set_message(t('Two-factor authentication is enabled but misconfigured. Please contact a site administrator.'), 'error');
      $form_state->setRedirect('user.page');
    }
  }

  /**
   * Login submit handler for TFA form redirection.
   *
   * Should be last invoked form submit handler for forms user_login and
   * user_login_block so that when the TFA process is applied the user will be
   * sent to the TFA form.
   *
   *
   * @param FormStateInterface $form_state
   */
  public function TfaLoginFormRedirect($form, &$form_state){
    $route = $form_state->getValue('tfa_redirect');
    if (isset($route)) {
      $form_state->setRedirect($route);
    }
  }

  /**
   * Check if TFA process has completed so authentication should not be stopped.
   *
   * @param $account User account
   * @return bool
   */
  protected function loginComplete($account) {
    // TFA master login allowed switch is set by tfa_login().
//    $tfa_session = $this->session->get('tfa');
//    if (isset($tfa_session[$account->id()]['login']) && $tfa_session[$account->id()]['login'] === TRUE) {
//      return TRUE;
//    }
    return FALSE;
  }


  /**
   * Determine if TFA process is ready.
   *
   * @param \Drupal\tfa\Plugin\TfaValidationInterface $tfaValidationPlugin
   * @return bool Whether process can begin or not.
   */
  protected function ready(TfaValidationInterface $tfaValidationPlugin) {
    return $tfaValidationPlugin->ready();
  }

  /**
   * Whether authentication should be allowed and not interrupted.
   *
   * If any plugin returns TRUE then authentication is not interrupted by TFA.
   *
   * @param \Drupal\tfa\Plugin\TfaLoginInterface $tfaLogin
   * @return bool
   */
  protected function loginAllowed(TfaLoginInterface $tfaLoginPlugin) {
//    if (!empty($tfaLoginPlugin)) {
//      foreach ($tfaLoginPlugin as $class) {
//        if ($class->loginAllowed()) {
//          return TRUE;
//        }
//      }
//    }
    return FALSE;
  }

  /**
   * Begin the TFA process.
   */
  protected function begin(TfaValidationInterface $tfaValidationPlugin) {
    // Invoke begin method on send validation plugins.
    if (method_exists($tfaValidationPlugin, 'begin')) {
      $tfaValidationPlugin->begin();
    }
  }


  /**
   * Generate account hash to access the TFA form.
   *
   * @param object $account User account.
   * @return string Random hash.
   */
  function tfa_login_hash($account) {
    // Using account login will mean this hash will become invalid once user has
    // authenticated via TFA.
    $data = implode(':', array($account->name, $account->pass, $account->login));
    return drupal_hash_base64($data);
  }


  protected function getLoginHash($account) {
    // Using account login will mean this hash will become invalid once user has
    // authenticated via TFA.
    $data = implode(':', array(
      $account->getUsername(),
      $account->getPassword(),
      $account->getLastLoginTime()
    ));
    return Crypt::hashBase64($data);
  }

}
