<?php

namespace Drupal\tfa\Tests;

use Base32\Base32;
use Drupal\simpletest\WebTestBase;
use Otp\GoogleAuthenticator;
use Otp\Otp;

/**
 * Tests the functionality of the Tfa plugins.
 *
 * @group Tfa
 */
class TfaValidationTest extends WebTestBase {

  /**
   * Object containing the external validation library.
   *
   * @var GoogleAuthenticator
   */
  protected $auth;

  /**
   * The validation plugin manager to fetch plugin information.
   *
   * @var \Drupal\tfa\TfaValidationPluginManager
   */
  protected $tfaValidationManager;

  /**
   * The secret.
   *
   * @var string
   */
  protected static $seed = "12345678901234567890";

  /**
   * {@inheritdoc}
   */
  public static $modules = ['tfa', 'node', 'encrypt', 'key'];

  /**
   * {@inheritdoc}
   */
  public function setUp() {
    // Enable TFA module and the test module.
    parent::setUp();

    // OTP class to do GA Login validation.
    $this->auth      = new \StdClass();
    $this->auth->otp = new Otp();
    $this->auth->ga  = new GoogleAuthenticator();
    $this->tfaValidationManager = \Drupal::service('plugin.manager.tfa.validation');
  }

  /**
   * Test login with TOTP.
   */
  public function testTfaTotp() {
    // Setup validation plugin.
    $account = $this->drupalCreateUser(['require tfa', 'access content']);
    $plugin = 'tfa_totp';
    $this->config('tfa.settings')
         ->set('enabled', 1)
         ->set('validate_plugin', $plugin)
         ->save();
    $validation_plugin = $this->tfaValidationManager->createInstance($plugin, ['uid' => $account->id()]);
    $validation_plugin->storeSeed(self::$seed);

    // Login.
    $edit = array(
      'name' => $account->getUsername(),
      'pass' => $account->pass_raw,
    );
    // Do not use drupalLogin as it does actual login.
    $this->drupalPostForm('user/login', $edit, t('Log in'));
    $this->assertText($this->uiStrings('app-desc'));
    // Get login hash. Could user tfa_login_hash() but would require reloading
    // account.
    $url_parts = explode('/', $this->url);
    $login_hash = array_pop($url_parts);

    // Try invalid code.
    $edit = array(
      'code' => substr(str_shuffle(self::$seed), 0, 6),
    );
    $this->drupalPostForm('tfa/' . $account->id() . '/' . $login_hash, $edit, t('Verify'));
    $this->assertText($this->uiStrings('invalid-code-retry'));

    // Try valid code.
    // Generate a code.
    $code = $this->auth->otp->totp(Base32::decode(self::$seed));
    $edit = array(
      'code' => $code,
    );

    $this->drupalPostForm('tfa/' . $account->id() . '/' . $login_hash, $edit, t('Verify'));
    $this->assertResponse(200);
    $this->assertText($account->getUsername());

    // Check for replay.
    $this->drupalLogout();
    $edit = array(
      'name' => $account->getUsername(),
      'pass' => $account->pass_raw,
    );

    // Do not use drupalLogin as it does actual login.
    $this->drupalPostForm('user/login', $edit, t('Log in'));
    $url_parts = explode('/', $this->url);
    $login_hash = array_pop($url_parts);

    $edit = array(
      'code' => $code,
    );

    $this->drupalPostForm('tfa/' . $account->id() . '/' . $login_hash, $edit, t('Verify'));
    $this->assertText($this->uiStrings('code-already-used'));
  }

  /**
   * Test login with HOTP.
   */
  public function testTfaHotp() {
    // Setup validation plugin.
    $account = $this->drupalCreateUser(['require tfa', 'access content']);
    $plugin = 'tfa_hotp';
    $this->config('tfa.settings')
         ->set('enabled', 1)
         ->set('validate_plugin', $plugin)
         ->save();
    $validation_plugin = $this->tfaValidationManager->createInstance($plugin, ['uid' => $account->id()]);
    $validation_plugin->storeSeed(self::$seed);

    // Login.
    $edit = array(
      'name' => $account->getUsername(),
      'pass' => $account->pass_raw,
    );
    // Do not use drupalLogin as it does actual login.
    $this->drupalPostForm('user/login', $edit, t('Log in'));
    $this->assertText($this->uiStrings('app-desc'));
    // Get login hash. Could user tfa_login_hash() but would require reloading
    // account.
    $url_parts = explode('/', $this->url);
    $login_hash = array_pop($url_parts);
    //
    // Try invalid code.
    $edit = array(
      'code' => substr(str_shuffle(self::$seed), 0, 6),
    );
    $this->drupalPostForm('tfa/' . $account->id() . '/' . $login_hash, $edit, t('Verify'));
    $this->assertText($this->uiStrings('invalid-code-retry'));

    // Try valid code.
    // Generate a code.
    $code = $this->auth->otp->hotp(Base32::decode(self::$seed), 1);
    $edit = array(
      'code' => $code,
    );

    $this->drupalPostForm('tfa/' . $account->id() . '/' . $login_hash, $edit, t('Verify'));
    $this->assertResponse(200);
    $this->assertText($account->getUsername());

    // Check for replay.
    $this->drupalLogout();
    $edit = array(
      'name' => $account->getUsername(),
      'pass' => $account->pass_raw,
    );

    // Do not use drupalLogin as it does actual login.
    $this->drupalPostForm('user/login', $edit, t('Log in'));
    $url_parts = explode('/', $this->url);
    $login_hash = array_pop($url_parts);

    $edit = array(
      'code' => $code,
    );

    $this->drupalPostForm('tfa/' . $account->id() . '/' . $login_hash, $edit, t('Verify'));
    $this->assertText($this->uiStrings('code-already-used'));

  }

  /**
   * Test login with TOTP fallback method.
   */
  public function testFallback() {
    // Setup validation plugin.
    $account = $this->drupalCreateUser(['require tfa', 'access content']);
    $plugin = 'tfa_totp';
    $fallback_plugin = 'tfa_recovery_code';
    $fallback_plugin_config = [
      $plugin => [$fallback_plugin => ['enable' => 1, 'weight' => -2]],
    ];
    $this->config('tfa.settings')
         ->set('enabled', 1)
         ->set('validate_plugin', $plugin)
         ->set('fallback_plugins', $fallback_plugin_config)
         ->save();
    $validation_plugin = $this->tfaValidationManager->createInstance($fallback_plugin, ['uid' => $account->id()]);
    $validation_plugin->storeCodes(['222 333 444']);

    // Login.
    $edit = array(
      'name' => $account->getUsername(),
      'pass' => $account->pass_raw,
    );
    // Do not use drupalLogin as it does actual login.
    $this->drupalPostForm('user/login', $edit, t('Log in'));
    // Get login hash. Could user tfa_login_hash() but would require reloading
    // account.
    $url_parts = explode('/', $this->url);
    $login_hash = array_pop($url_parts);

    // Try invalid recovery code.
    $edit = array(
      'code' => '111 222 333',
    );
    $this->drupalPostForm('tfa/' . $account->id() . '/' . $login_hash, $edit, t('Verify'));
    $this->assertText($this->uiStrings('invalid-recovery-code'));

    // Try valid recovery code.
    $edit = array(
      'code' => '222 333 444',
    );
    $this->drupalPostForm('tfa/' . $account->id() . '/' . $login_hash, $edit, t('Verify'));
    $this->assertResponse(200);
    $this->assertText($account->getUsername());
  }

  /**
   * TFA module user interface strings.
   *
   * @param string $id
   *   ID of string.
   *
   * @return string
   *   UI message for corresponding id.
   */
  protected function uiStrings($id) {
    switch ($id) {
      case 'invalid-recovery-code':
        return 'Invalid recovery code.';

      case 'app-desc':
        return 'Verification code is application generated and 6 digits long.';

      case 'invalid-code-retry':
        return 'Invalid application code. Please try again.';

      case 'code-already-used':
        return 'Invalid code, it was recently used for a login. Please try a new code.';
    }
  }

}
