<?php

/**
 * @file
 * Contains Drupal\tfa\Form\EntryForm.
 */

namespace Drupal\tfa\Form;

use Drupal\Core\Form\ConfigFormBase;
use Drupal\Core\Form\FormStateInterface;

class EntryForm extends ConfigFormBase {

  /**
   * {@inheritdoc}
   */
  public function getFormID() {
    return 'tfa_entry_form';
  }

  /**
   * {@inheritdoc}
   */
  public function buildForm(array $form, FormStateInterface $form_state) {
    $account = $this->userStorage->load($form_state->get('uid'));

    //$tfa = tfa_get_process($account);

    /*
    // Check flood tables.
    if (_tfa_hit_flood($tfa)) {
      \Drupal::moduleHandler()->invokeAll('tfa_flood_hit', [$tfa->getContext()]);
      return drupal_access_denied();
    }
    */

    // Get TFA plugins form.
    //$form = $tfa->getForm($form, $form_state);
    //if ($tfa->hasFallback()) {
    $form['actions']['fallback'] = array(
      '#type' => 'submit',
      '#value' => t("Can't access your account?"),
      '#submit' => array('tfa_form_submit'),
      '#limit_validation_errors' => array(),
      '#weight' => 20,
    );
    //}

    // Set account element.
    $form['account'] = array(
      '#type' => 'value',
      '#value' => $account,
    );

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
    parent::submitForm($form, $form_state);
  }

  /**
   * {@inheritdoc}
   */
  protected function getEditableConfigNames() {
    return ['tfa.settings'];
  }

}
