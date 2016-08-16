<?php

namespace Drupal\tfa\Form;

use Drupal\Core\Form\FormBase;
use Drupal\Core\Form\FormStateInterface;
use Drupal\Core\Url;
use Drupal\tfa\TfaDataTrait;
use Drupal\tfa\TfaSetupPluginManager;
use Drupal\user\UserDataInterface;
use Drupal\user\UserInterface;
use Symfony\Component\DependencyInjection\ContainerInterface;

/**
 * TFA Basic account setup overview page.
 */
class BasicOverview extends FormBase {
  use TfaDataTrait;

  /**
   * The setup plugin manager to fetch setup information.
   *
   * @var \Drupal\tfa\TfaLoginPluginManager
   */
  protected $tfaSetup;

  /**
   * Provides the user data service object.
   *
   * @var \Drupal\user\UserDataInterface
   */
  protected $userData;

  /**
   * BasicOverview constructor.
   *
   * @param \Drupal\user\UserDataInterface $user_data
   *   The user data service.
   * @param \Drupal\tfa\TfaSetupPluginManager $tfa_setup_manager
   *   The setup plugin manager.
   */
  public function __construct(UserDataInterface $user_data, TfaSetupPluginManager $tfa_setup_manager) {
    $this->userData = $user_data;
    $this->tfaSetup = $tfa_setup_manager;
  }

  /**
   * {@inheritdoc}
   */
  public static function create(ContainerInterface $container) {
    return new static(
      $container->get('user.data'),
      $container->get('plugin.manager.tfa.setup')
    );
  }

  /**
   * {@inheritdoc}
   */
  public function getFormId() {
    return 'tfa_base_overview';
  }

  /**
   * {@inheritdoc}
   */
  public function buildForm(array $form, FormStateInterface $form_state, UserInterface $user = NULL) {
    $output['info'] = [
      '#type' => 'markup',
      '#markup' => '<p>' . $this->t('Two-factor authentication (TFA) provides
      additional security for your account. With TFA enabled, you log in to
      the site with a verification code in addition to your username and
      password.') . '</p>',
    ];
    // $form_state['storage']['account'] = $user;.
    $configuration = $this->config('tfa.settings')->getRawData();
    $user_tfa = $this->tfaGetTfaData($user->id(), $this->userData);
    $enabled = isset($user_tfa['status']) && $user_tfa['status'] ? TRUE : FALSE;

    if (!empty($user_tfa)) {
      $date_formatter = \Drupal::service('date.formatter');
      if ($enabled && !empty($user_tfa['data']['plugins'])) {
        if ($this->currentUser()->hasPermission('disable own tfa')) {
          $status_text = $this->t('Status: <strong>TFA enabled</strong>, set
          @time. <a href=":url">Disable TFA</a>', [
            '@time' => $date_formatter->format($user_tfa['saved']),
            ':url' => URL::fromRoute('tfa.disable', ['user' => $user->id()])->toString(),
          ]);
        }
        else {
          $status_text = $this->t('Status: <strong>TFA enabled</strong>, set @time.', [
            '@time' => $date_formatter->format($user_tfa['saved']),
          ]);
        }
      }
      else {
        $status_text = $this->t('Status: <strong>TFA disabled</strong>, set @time.', [
          '@time' => $date_formatter->format($user_tfa['saved']),
        ]);
      }
      $output['status'] = [
        '#type' => 'markup',
        '#markup' => '<p>' . $status_text . '</p>',
      ];
    }

    if ($configuration['enabled']) {
      $enabled = isset($user_tfa['status']) && $user_tfa['status'] ? TRUE : FALSE;
      // Validation plugin setup.
      $enabled_plugin = $configuration['validation_plugin'];
      $enabled_fallback_plugin = '';
      if (isset($configuration['fallback_plugins'][$enabled_plugin])) {
        $enabled_fallback_plugin = key($configuration['fallback_plugins'][$enabled_plugin]);
      }

      $output['app'] = $this->tfaPluginSetupFormOverview($enabled_plugin, $user, $user_tfa);

      if ($enabled) {
        $login_plugins = $configuration['login_plugins'];
        foreach ($login_plugins as $lplugin_id) {
          $output[$lplugin_id] = $this->tfaPluginSetupFormOverview($lplugin_id, $user, $user_tfa);

        }

        $send_plugin = $configuration['send_plugin'];
        if ($send_plugin) {
          $output[$send_plugin] = $this->tfaPluginSetupFormOverview($send_plugin, $user, $user_tfa);
        }

        if ($enabled_fallback_plugin) {
          // Fallback Setup.
          $output['recovery'] = $this->tfaPluginSetupFormOverview($enabled_fallback_plugin, $user, $user_tfa);
        }
      }
    }
    else {
      $output['disabled'] = [
        '#type' => 'markup',
        '#markup' => '<b>Currently there are no enabled plugins.</b>',
      ];
    }

    return $output;
  }

  /**
   * Get TFA basic setup action links for use on overview page.
   *
   * @param string $plugin
   *   The setup plugin.
   * @param object $account
   *   Current user account.
   * @param array $user_tfa
   *   Tfa data for current user.
   *
   * @return array
   *   Render array
   */
  protected function tfaPluginSetupFormOverview($plugin, $account, array $user_tfa) {
    $enabled = isset($user_tfa['status']) && $user_tfa['status'] ? TRUE : FALSE;

    $output = [];
    $params = [
      'enabled' => $enabled,
      'account' => $account,
      'plugin_id' => $plugin,
    ];
    $output = $this->tfaSetup
                ->createInstance($plugin . '_setup', ['uid' => $account->id()])
                ->getOverview($params);
    return $output;
  }

  /**
   * {@inheritdoc}
   */
  public function validateForm(array &$form, FormStateInterface $form_state) {
  }

  /**
   * {@inheritdoc}
   */
  public function submitForm(array &$form, FormStateInterface $form_state) {
  }

}
