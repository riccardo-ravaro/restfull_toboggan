<?php

/**
 * @file
 * Contains \Drupal\restful_toboggan\Plugin\Authentication\BasicAuthenticationToboggan
 */

namespace Drupal\restful_toboggan\Plugin\Authentication;

use Drupal\restful\Exception\FloodException;
use Drupal\restful\Http\Request;
use Drupal\restful\Http\RequestInterface;
use Drupal\restful\Plugin\authentication\Authentication;

/**
 * Class BasicAuthenticationToboggan
 * @package Drupal\restful_toboggan\Plugin\Authentication
 *
 * @Authentication(
 *   id = "basic_auth_toboggan",
 *   label = "Basic authentication Toboggan",
 *   description = "Authenticate requests based on basic auth by email or by username",
 * )
 */
class BasicAuthenticationToboggan extends Authentication
{

  /**
   * {@inheritdoc}
   */
  public function applies(RequestInterface $request)
  {
    //if (variable_get('restful_skip_basic_auth', false)) {
    // Skip basic auth. The variable may be set if .htaccess password is set
    // on the server.
    //return null;
    //}
    $username = $request->getUser();
    $password = $request->getPassword();

    return isset($username) && isset($password);
  }

  /**
   * {@inheritdoc}
   *
   * @see user_login_authenticate_validate().
   */
  public function authenticate(RequestInterface $request)
  {
    $username = $request->getUser();
    $password = $request->getPassword();

    // Do not allow any login from the current user's IP if the limit has been
    // reached. Default is 50 failed attempts allowed in one hour. This is
    // independent of the per-user limit to catch attempts from one IP to log
    // in to many different user accounts.  We have a reasonably high limit
    // since there may be only one apparent IP for all users at an institution.
    if (!flood_is_allowed('failed_login_attempt_ip', variable_get('user_failed_login_ip_limit', 50), variable_get('user_failed_login_ip_window', 3600))) {
      throw new FloodException(format_string('Rejected by ip flood control.'));
    }

    if (filter_var($username, FILTER_VALIDATE_EMAIL)) {

      if (!$uid = db_query_range("SELECT uid FROM {users} WHERE LOWER(mail) = LOWER(:mail) AND status = 1", 0, 1, array(':mail' => $username))->fetchField()) {
        // Always register an IP-based failed login event.

        flood_register_event('failed_login_attempt_ip', variable_get('user_failed_login_ip_window', 3600), ip_address());
        return null;
      } else {
        $username = db_query_range("SELECT name FROM {users} WHERE LOWER(mail) = LOWER(:mail) AND status = 1", 0, 1, array(':mail' => $username))->fetchField();

      }
    } else {

      if (!$uid = db_query_range("SELECT uid FROM {users} WHERE name = :name AND status = 1", 0, 1, array(':name' => $username))->fetchField()) {
        // Always register an IP-based failed login event.

        flood_register_event('failed_login_attempt_ip', variable_get('user_failed_login_ip_window', 3600), ip_address());
        return null;
      }
    }

    if (variable_get('user_failed_login_identifier_uid_only', false)) {
      // Register flood events based on the uid only, so they apply for any
      // IP address. This is the most secure option.
      $identifier = $uid;
    } else {
      // The default identifier is a combination of uid and IP address. This
      // is less secure but more resistant to denial-of-service attacks that
      // could lock out all users with public user names.
      $identifier = $uid; // . '-' . ip_address();
    }

    // Don't allow login if the limit for this user has been reached.
    // Default is to allow 5 failed attempts every 6 hours.

    if (flood_is_allowed('failed_login_attempt_user', variable_get('user_failed_login_user_limit', 5), variable_get('user_failed_login_user_window', 21600), $identifier)) {
      // We are not limited by flood control, so try to authenticate.

      if ($uid = user_authenticate($username, $password)) {
        // Clear the user based flood control.

        flood_clear_event('failed_login_attempt_user', $identifier);

        $user = user_load($uid);

        return user_load($uid);
      }

      flood_register_event('failed_login_attempt_user', variable_get('user_failed_login_user_window', 3600), $identifier);
    } else {
      flood_register_event('failed_login_attempt_user', variable_get('user_failed_login_user_window', 3600), $identifier);
      throw new FloodException(format_string('Rejected by user flood control.'));
    }
  }

}
