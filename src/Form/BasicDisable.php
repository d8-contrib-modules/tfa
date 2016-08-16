<?php

namespace Drupal\tfa\Form;

use Drupal\Component\Plugin\PluginManagerInterface;
use Drupal\Core\Form\FormBase;
use Drupal\Core\Form\FormStateInterface;
use Drupal\tfa\TfaDataTrait;
use Drupal\user\Entity\User;
use Drupal\user\UserDataInterface;
use Symfony\Component\DependencyInjection\ContainerInterface;

/**
 * TFA disable form router.
 */
class BasicDisable extends FormBase {
  use TfaDataTrait;
  /**
   * The plugin manager to fetch plugin information.
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
   * BasicDisable constructor.
   *
   * @param \Drupal\Component\Plugin\PluginManagerInterface $manager
   *   The plugin manager to fetch plugin information.
   * @param \Drupal\user\UserDataInterface $user_data
   *   The user data object to store user information.
   */
  public function __construct(PluginManagerInterface $manager, UserDataInterface $user_data) {
    $this->manager = $manager;
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
      $container->get('plugin.manager.tfa.validation'),
      $container->get('user.data')
    );
  }

  /**
   * {@inheritdoc}
   */
  public function getFormId() {
    return 'tfa_disable';
  }

  /**
   * {@inheritdoc}
   */
  public function buildForm(array $form, FormStateInterface $form_state, User $user = NULL) {
    $account = User::load($this->currentUser()->id());

    $storage = $form_state->getStorage();
    $storage['account'] = $user;

    // @todo Check require permissions and give warning about being locked out.
    if ($account->id() != $user->id() && $account->hasPermission('administer users')) {
      $preamble_desc = $this->t('Are you sure you want to disable TFA on account
      %name?', ['%name' => $user->getUsername()]);

      $notice_desc = $this->t('TFA settings and data will be lost. %name can
      re-enable TFA again from their profile.', ['%name' => $user->getUsername()]);
    }
    else {
      $preamble_desc = $this->t('Are you sure you want to disable your
      two-factor authentication setup?');

      $notice_desc = $this->t("Your settings and data will be lost. You can
      re-enable two-factor authentication again from your profile.");
    }
    $form['preamble'] = [
      '#prefix' => '<p class="preamble">',
      '#suffix' => '</p>',
      '#markup' => $preamble_desc,
    ];
    $form['notice'] = [
      '#prefix' => '<p class="preamble">',
      '#suffix' => '</p>',
      '#markup' => $notice_desc,
    ];

    $form['account']['current_pass'] = [
      '#type' => 'password',
      '#title' => $this->t('Confirm your current password'),
      '#description_display' => 'before',
      '#size' => 25,
      '#weight' => -5,
      '#attributes' => ['autocomplete' => 'off'],
      '#required' => TRUE,
    ];
    $form['account']['mail'] = [
      '#type' => 'value',
      '#value' => $user->getEmail(),
    ];
    $form['actions']['submit'] = [
      '#type' => 'submit',
      '#value' => $this->t('Disable'),
    ];
    $form['actions']['cancel'] = [
      '#type' => 'submit',
      '#value' => $this->t('Cancel'),
      '#limit_validation_errors' => [],
      '#submit' => ['::cancelForm'],
    ];

    $form_state->setStorage($storage);

    return $form;
  }

  /**
   * {@inheritdoc}
   */
  public function validateForm(array &$form, FormStateInterface $form_state) {
    $user = User::load($this->currentUser()->id());
    $storage = $form_state->getStorage();
    $account = $storage['account'];
    // Allow administrators to disable TFA for another account.
    if ($account->id() != $user->id() && $user->hasPermission('administer users')) {
      $account = $user;
    }
    // Check password.
    $current_pass = \Drupal::service('password')->check(trim($form_state->getValue('current_pass')), $account->getPassword());
    if (!$current_pass) {
      $form_state->setErrorByName('current_pass', $this->t("Incorrect password."));
    }
  }

  /**
   * {@inheritdoc}
   */
  public function submitForm(array &$form, FormStateInterface $form_state) {

    $storage = $form_state->getStorage();
    $values = $form_state->getValues();
    $account = $storage['account'];
    if ($values['op'] === $values['cancel']) {
      drupal_set_message($this->t('TFA disable canceled.'));
      $form_state->setRedirect('tfa.overview', ['user' => $account->id()]);
      return;
    }

    // Delete all user data.
    $this->deleteUserData('tfa', null, $account->id(), $this->userData);

    \Drupal::logger('tfa')->notice('TFA disabled for user @name UID @uid', [
      '@name' => $account->getUsername(),
      '@uid' => $account->id(),
    ]);

    // @todo Not working, not sure why though.
    // E-mail account to inform user that it has been disabled.
    $params = ['account' => $account];
    \Drupal::service('plugin.manager.mail')->mail('tfa', 'tfa_disabled_configuration', $account->getEmail(), $account->getPreferredLangcode(), $params);

    drupal_set_message($this->t('TFA has been disabled.'));
    $form_state->setRedirect('tfa.overview', ['user' => $account->id()]);
  }

  /**
   * {@inheritdoc}
   */
  public function cancelForm(array &$form, FormStateInterface $form_state) {
    drupal_set_message('TFA Disable cancelled.', 'warning');
    $form_state->setRedirect('tfa.overview', ['user' => $this->currentUser()->id()]);
  }

}
