<?php

/**
 * @file
 * Contains Drupal\tfa\Annotation\TfaSetup
 */

namespace Drupal\tfa\Annotation;

use Drupal\Component\Annotation\Plugin;

/**
 * Defines a TFA Setup annotation object.
 *
 * @Annotation
 */
class TfaSetup extends Plugin {

  /**
   * The plugin ID.
   *
   * @var string
   */
  public $id;

  /**
   * The human-readable name of the Tfa setup.
   *
   * @ingroup plugin_translatable
   *
   * @var \Drupal\Core\Annotation\Translation
   */
  public $title;

  /**
   * The description shown to users.
   *
   * @ingroup plugin_translatable
   *
   * @var \Drupal\Core\Annotation\Translation
   */
  public $description;

  /**
   * The helper metadata for setup plugin
   *
   * @var string[]
   */
  public $help_links;


}
