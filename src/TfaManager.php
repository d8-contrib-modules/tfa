<?php
/**
 * @file TfaManager
 * Contains the TfaManager service.
 */

namespace Drupal\tfa;


use Drupal\tfa\Tfa;
use Drupal\user\Entity\User;
use Drupal\Component\Utility\Crypt;


class TfaManager {


  /**
   * Get Tfa object in the account's current context.
   *
   * @param $account User account object
   * @return Tfa
   */
  //function _tfa_get_process($account) {
  public function getProcess($account) {
    $tfa = &drupal_static(__FUNCTION__);
    if (!isset($tfa)) {
      $context = $this->getContext($account);
      if (empty($context['plugins'])) {
        $context = $this->startContext($account);
      }
      try {
        // instansiate all plugins
        $tfa = new Tfa($context['plugins'], $context);
      } catch (\Exception $e) {
        $tfa = FALSE;
      }
    }
    return $tfa;
  }

  /**
   * Context for account TFA process.
   *
   * @param User $account
   * @return array
   * @see _tfa_start_context() for format
   */
  //function _tfa_get_context(User $account) {
  public function getContext(User $account) {
    $context = array();
//  if (isset($_SESSION['tfa'][$account->id()])) {
//    $context = $_SESSION['tfa'][$account->id()];
//  }
    // Allow other modules to modify TFA context.
    \Drupal::moduleHandler()->alter('tfa_context', $context);
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
   *
   * @TODO TBD on purpose of $api defines the class name of the plugins, but we need to load
   * them by the plugin name. Is it actually doing us any good?
   */
  //function _tfa_start_context($account) {
  public function startContext($account) {
    $context = array('uid' => $account->id(), 'plugins' => array());
    $plugins = array();
    $fallback_plugins = array();

    $api = \Drupal::moduleHandler()->invokeAll('tfa_api', []);
    $settings = \Drupal::config('tfa.settings');
    if (\Drupal::config('tfa.settings')->get('login_plugins')) {
      $plugins = \Drupal::config('tfa.settings')->get('login_plugins');
    }

    if (\Drupal::config('tfa.settings')->get('fallback_plugins')) {
      $fallback_plugins = \Drupal::config('tfa.settings')->get('fallback_plugins');
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
    $validate = \Drupal::config('tfa.settings')->get('validate_plugins');
    foreach($validate as $key => $value){
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
    \Drupal::moduleHandler()->alter('tfa_context', $context);
    $this->setContext($account, $context);
    return $context;
  }

  /**
   * Set context for account's TFA process.
   *
   * @param $account User account
   * @param array $context Context array
   * @see tfa_start_context() for context format
   */
  public function setContext($account, $context) {
    $_SESSION['tfa'][$account->id()] = $context;
    $_SESSION['tfa'][$account->id()]['uid'] = $account->id();
    // Clear existing static TFA process.
    drupal_static_reset('tfa_get_process');
  }

  /**
   * Check if TFA process has completed so authentication should not be stopped.
   *
   * @param $account User account
   * @return bool
   */
  //function _tfa_login_complete($account) {
  public function loginComplete($account) {
    // TFA master login allowed switch is set by tfa_login().
    if (isset($_SESSION['tfa'][$account->uid]['login']) && $_SESSION['tfa'][$account->uid]['login'] === TRUE) {
      return TRUE;
    }
    return FALSE;
  }

  /**
   * Generate account hash to access the TFA form.
   *
   * @param object $account User account.
   * @return string Random hash.
   */
  //function tfa_login_hash($account) {
  public function getLoginHash($account) {
    // Using account login will mean this hash will become invalid once user has
    // authenticated via TFA.
    $data = implode(':', array($account->getUsername() , $account->getPassword(), $account->getLastLoginTime()));
    return Crypt::hashBase64($data);
  }


  /**
   * Authenticate the user.
   *
   * Does basically the same thing that user_login_finalize does but with our own custom
   * hooks.
   *
   * @param $account User account object.
   */
  //function _tfa_login($account) {
  public function login($account) {
    \Drupal::currentUser()->setAccount($account);

    // Update the user table timestamp noting user has logged in.
    $account->setLastLoginTime(REQUEST_TIME);
    \Drupal::entityManager()
      ->getStorage('user')
      ->updateLastLoginTimestamp($account);
    // Regenerate the session ID to prevent against session fixation attacks.
    \Drupal::service('session')->migrate();
    \Drupal::service('session')->set('uid', $account->id());

    //watchdog('tfa', 'Session opened for %name.', array('%name' => $user->getUsername()));
    // Clear existing context and set master authenticated context.
    $this->clearContext($account);
    $_SESSION['tfa'][$account->id()]['login'] = TRUE;

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
   */
  public function clearContext($account) {
    unset($_SESSION['tfa'][$account->uid]);
  }


}