<?php
/**
 * @file TfaManager
 * Contains the TfaManager service.
 */

namespace Drupal\tfa;


use Drupal\Core\Config\ConfigFactoryInterface;
use \Drupal\tfa\Form\TfaLoginForm;
use Drupal\Core\Entity\EntityManagerInterface;
use Drupal\Core\Extension\ModuleHandlerInterface;
use Drupal\Core\Session\AccountProxyInterface;
use Drupal\user\Entity\User;
use Drupal\Component\Utility\Crypt;
use Symfony\Component\HttpFoundation\RequestStack;
use Symfony\Component\HttpFoundation\Session\SessionInterface;

/**
 *
 * @todo finish cleaning up $SESSION
 *
 * Class TfaManager
 * @package Drupal\tfa
 */
class TfaManager {

  /**
   * @var \Drupal\Core\Extension\ModuleHandlerInterface
   */
  protected $moduleHander;

  /**
   * @var \Drupal\Core\Config\ConfigFactoryInterface
   */
  //protected $configFactory;

  /**
   * @var \Drupal\Core\Session\AccountProxyInterface
   */
  protected $currentUser;

  /**
   * @var \Drupal\Core\Entity\EntityManagerInterface
   */
  protected $entityManager;

  /**
   * @var \Symfony\Component\HttpFoundation\Session\SessionInterface
   */
  protected $session;

  /**
   * @var \Drupal\Core\Config\ImmutableConfig
   */
  protected $tfaSettings;

  /**
   * @var null|\Symfony\Component\HttpFoundation\Request
   */
  protected $request;

  /**
   * @var
   */
  protected $tfa;

  /**
   * @var \Drupal\tfa\Form\TfaLoginForm
   */
  protected $tfaValidation;

  /**
   * @param \Drupal\Core\Extension\ModuleHandlerInterface $module_handler
   * @param \Drupal\Core\Config\ConfigFactoryInterface $config_factory
   * @param \Drupal\Core\Session\AccountProxyInterface $current_user
   * @param \Drupal\Core\Entity\EntityManagerInterface $entity_manager
   * @param \Symfony\Component\HttpFoundation\Session\SessionInterface $session
   */
  function __construct(ModuleHandlerInterface $module_handler, ConfigFactoryInterface $config_factory, AccountProxyInterface $current_user, EntityManagerInterface $entity_manager, SessionInterface $session, RequestStack $request_stack, TfaLoginForm $tfaValidation ) {
    $this->moduleHander = $module_handler;
    //$this->configFactory = $config_factory;
    $this->currentUser = $current_user;
    $this->entityManager = $entity_manager;
    $this->session = $session;
    $this->tfaSettings = $config_factory->get('tfa.settings');
    $this->request = $request_stack->getCurrentRequest();
    $this->tfaValidation = $tfaValidation;
  }


  /**
   * Get Tfa object in the account's current context.
   *
   * @param $account User account object
   * @return Tfa
   * @deprecated
   */
  public function getProcess($account) {
    //$tfa = &drupal_static(__FUNCTION__);
    if (!isset($this->tfa)) {
      $context = $this->getContext($account);
      if (empty($context['plugins'])) {
        $context = $this->startContext($account);
      }
      try {
        // instansiate all plugins
        $this->tfa = new Tfa($context['plugins'], $context);
      }
      catch (\Exception $e) {
        $this->tfa = FALSE;
      }
    }
    return $this->tfa;
  }

  /**
   * Context for account TFA process.
   *
   * @param User $account
   * @return array
   * @see _tfa_start_context() for format
   * @deprecated
   */
  public function getContext(User $account) {
    $context = array();
    $tfaSession = $this->request->getSession()->get('tfa');
//    if (!empty($tfaSession[$account->id()])) {
//      $context = $tfaSession[$account->id()];
//    }
    // Allow other modules to modify TFA context.
    $this->moduleHander->alter('tfa_context', $context);
    return $context;
  }


  /**
   * Start context for TFA.
   *
   * @param User $account
   * @return array
   *   array(
   *     'uid' => 9,
   *     'plugins' => array(
   *       'validate' => 'TfaMySendPlugin',
   *       'login' => arrray('TfaMyLoginPlugin'),
   *       'fallback' => array('TfaMyRecoveryCodePlugin'),
   *       'setup' => 'TfaMySetupPlugin',
   *     ),
   *
   * @TODO TBD on purpose of $api defines the class name of the plugins, but we need to load
   * them by the plugin name. Is it actually doing us any good?
   *
   * @deprecated
   */
  public function startContext($account) {
    $context = array('uid' => $account->id(), 'plugins' => array());
    $plugins = array();
    $fallback_plugins = array();

    $api = $this->moduleHander->invokeAll('tfa_api', []);
    if ($this->tfaSettings->get('login_plugins')) {
      $plugins = $this->tfaSettings->get('login_plugins');
    }

    if ($this->tfaSettings->get('fallback_plugins')) {
      $fallback_plugins = $this->tfaSettings->get('fallback_plugins');
    }

    // Add login plugins.
    //@TODO This won't work the way it is. Need to refactor like we did for validate plguins.
    foreach ($plugins as $key) {
      if (array_key_exists($key, $api)) {
        $context['plugins']['login'][] = $api[$key]['class'];
      }
    }
    // Add validate.
    //@TODO Figure out why D8 decided to allow multiple validate plugins.
    $validate = $this->tfaSettings->get('validate_plugins');
    foreach ($validate as $key => $value) {
      if (!empty($validate) && array_key_exists($key, $api)) {
        $context['plugins']['validate'] = $key;
      }
    }

    // Add fallback plugins.
    foreach ($fallback_plugins as $key) {
      if (array_key_exists($key, $api)) {
        $context['plugins']['fallback'][] = $api[$key]['class'];
      }
    }
    // Allow other modules to modify TFA context.
    $this->moduleHander->alter('tfa_context', $context);
    $this->setContext($account, $context);
    return $context;
  }

  /**
   * Set context for account's TFA process.
   *
   * @param $account User account
   * @param array $context Context array
   * @see tfa_start_context() for context format
   * @deprecated
   */
  public function setContext($account, $context) {

    $context = array_merge(['uid' => $account->id()], $context);
    $this->session->set('tfa', [$account->id() => $context]);
    // Clear existing static TFA process.
    $this->tfa = NULL;
  }

  /**
   * Context for account TFA process.
   *
   * @param object $account
   *   User account
   * @return array
   *   @see tfa_start_context() for format
   */
  function tfa_get_context($account) {
    $context = array();
    if (isset($_SESSION['tfa'][$account->uid])) {
      $context = $_SESSION['tfa'][$account->uid];
    }
    // Allow other modules to modify TFA context.
    //drupal_alter('tfa_context', $context);
    return $context;
  }



  /**
   * Authenticate the user.
   *
   * Does basically the same thing that user_login_finalize does but with our own custom
   * hooks.
   *
   * @deprecated
   *
   * @TODO Use user_login_finalize and utilize the user_login hook that it implements to
   * do the additional flood stuff.
   *
   * @param $account User account object.
   * @deprecated
   */
  public function login($account) {
    //@todo Implement flood controls for the TFA login.

    // Truncate flood for user.
    //flood_clear_event('tfa_begin');
    //$identifier = variable_get('user_failed_login_identifier_uid_only', FALSE) ? $account->uid : $account->uid . '-' . ip_address();
    //flood_clear_event('tfa_user', $identifier);
    //$edit = array();
    //user_module_invoke('login', $edit, $user);
  }

  /**
   * Remove context for account.
   *
   * @param object $account
   *   User account object
   * @deprecated
   */
  public function clearContext($account) {
    unset($this->session->get('tfa')[$account->uid]);
  }


  /**
   * Validate access to TFA code entry form.
   * @deprecated
   */
  public function entryAccess($account, $url_hash) {
    // Generate a hash for this account.
    $hash = $this->tfaValidation->tfa_login_hash($account);
    $context = $this->tfa_get_context($account);
    return $hash === $url_hash && !empty($context) && $context['uid'] === $account->uid;
    return TRUE;
  }

}
