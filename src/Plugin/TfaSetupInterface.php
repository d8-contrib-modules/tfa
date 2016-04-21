<?php

/**
 * @file
 * Contains \Drupal\tfa\TfaSetupInterface.
 */

namespace Drupal\tfa\Plugin;

use Drupal\Core\Form\FormStateInterface;

/**
 * Interface TfaSetupInterface
 *
 * Setup plugins are used by TfaSetup for configuring a plugin.
 *
 * Implementations of a begin plugin should also be a validation plugin.
 */
interface TfaSetupInterface {

  /**
   * @param array $form
   * @param FormStateInterface $form_state
   */
  public function getSetupForm(array $form, FormStateInterface &$form_state);

  /**
   * @param array $form
   * @param FormStateInterface $form_state
   */
  public function validateSetupForm(array $form, FormStateInterface &$form_state);

  /**
   * @param array $form
   * @param FormStateInterface $form_state
   * @return bool
   */
  public function submitSetupForm(array $form, FormStateInterface &$form_state);

  /**
   * Returns a list of links containing helpful information for plugin use.
   * @return string[]
   */
  public function getHelpLinks();

}