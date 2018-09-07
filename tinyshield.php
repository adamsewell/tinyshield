<?php
/*
Plugin Name: tinyShield
Version: 0.1.4
Description: tinyShield is a security plugin that utilizes real time blacklists and also crowd sources attacker data for enhanced protection.
Plugin URI: https://tinyshield.me
Author: tinyElk Studios
Author URI: https://adamsewell.me

	This plugin is free software: you can redistribute it and/or modify
	it under the terms of the GNU General Public License as published by
	the Free Software Foundation, either version 2 of the License, or
	(at your option) any later version.

	This plugin is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU General Public License for more details.

	You should have received a copy of the GNU General Public License
	along with this plugin.  If not, see <http://www.gnu.org/licenses/>.
*/
if(!defined('ABSPATH')) die();

include_once(plugin_dir_path(__FILE__) . 'lib/blacklist_tables.php');
include_once(plugin_dir_path(__FILE__) . 'lib/whitelist_tables.php');
include_once(plugin_dir_path(__FILE__) . 'lib/perm_whitelist_tables.php');

class tinyShield{

	private static $tinyshield_report_url = 'https://endpoint.tinyshield.me/report';
	private static $tinyshield_check_url = 'https://endpoint.tinyshield.me/checkv2';
	private static $tinyshield_signup_url = 'https://tinyshield.me/signup';
	private static $tinyshield_activation_url = 'https://endpoint.tinyshield.me/activate';

	public function __construct(){
		//default stuff
		register_activation_hook(__FILE__, 'tinyShield::on_activation');

		add_action('admin_menu', 'tinyShield::add_menu');
		add_action('admin_notices', 'tinyShield::notices');
		add_action('plugins_loaded', 'tinyShield::maybe_block', 0);

		//hook into the failed login attempt and report home
		add_filter('wp_login_failed', 'tinyShield::log_failed_login');

	}

	public static function notices(){
		$options = get_option('tinyshield_options');
?>
		<?php if(empty($options['site_activation_key'])): ?>
			<div class="error"><p><strong><?php _e('tinyShield: This site is not registered. Before this plugin will work, you must register your site and activate the plugin using the key provided. tinyShield settings can be found under the Settings menu. <a target="_blank" href="' . esc_attr(self::$tinyshield_signup_url) . '">tinyShield Registration</a>', 'tinyshield');?></strong></p></div>
		<?php endif; ?>
<?php
	}

	public static function add_menu(){
		if(function_exists('add_options_page')){
			add_options_page('tinyShield', 'tinyShield', 'manage_options', basename(__FILE__), 'tinyShield::display_options');
		}
	}

	public function on_activation(){
		$options = get_option('tinyshield_options');
		$cached_blacklist = get_option('tinyshield_cached_blacklist');
		$cached_whitelist = get_option('tinyshield_cached_whitelist');
		$cached_perm_whitelist = get_option('tinyshield_cached_perm_whitelist');

		if(!is_array($options)){
			$options = array();
			update_option('tinyshield_options', $options);
		}

		if(!is_array($cached_blacklist)){
			$cached_blacklist = array();
			update_option('tinyshield_cached_blacklist', $cached_blacklist);
		}

		if(!is_array($cached_perm_whitelist)){
			$cached_perm_whitelist = array();
			$cached_perm_whitelist[ip2long(self::get_valid_ip())] = json_encode(array('expires' => strtotime('+30 years')));
			update_option('tinyshield_cached_perm_whitelist', $cached_perm_whitelist);
		}

		if(!is_array($cached_whitelist)){
			$cached_whitelist = array();
			update_option('tinyshield_cached_whitelist', $cached_whitelist);
		}
	}

	public static function maybe_block(){
		$ip = self::get_valid_ip();
		$cached_blacklist = get_option('tinyshield_cached_blacklist');

		self::clean_up_lists();

		//check if valid ip and check the local whitelist
		if($ip && !self::check_ip_whitelist($ip)){

			//check local cached ips
			if(!empty($cached_blacklist) && array_key_exists(ip2long($ip), $cached_blacklist)){
				header('HTTP/1.0 403 Forbidden');
				exit;
			}

			//if not in cache, remote lookup
			if(self::check_ip_blacklist($ip)){
				header('HTTP/1.0 403 Forbidden');
				exit;
			}
		}
	}

	private static function check_ip_blacklist($ip){
		$options = get_option('tinyshield_options');
		$cached_blacklist = get_option('tinyshield_cached_blacklist');
		$cached_whitelist = get_option('tinyshield_cached_whitelist');

		$response = wp_remote_post(
			self::$tinyshield_check_url . '/' . ip2long($ip),
			array(
				'body' => array(
					'activation_key' => urlencode($options['site_activation_key']),
					'requesting_site' => urlencode(site_url())
				)
			)
		);

		if(!empty($response['body'])){
			$list_data = json_decode($response['body']);
			$list_data->expires = strtotime('+24 hours');
		}

		if(!is_wp_error($response) && is_object($list_data) && $list_data->action == 'block'){ //blacklist
			$cached_blacklist[ip2long($ip)] = json_encode($list_data);
			update_option('tinyshield_cached_blacklist', $cached_blacklist);
			return true;
		}elseif(!is_wp_error($response) && is_object($list_data) && $list_data->action == 'allow'){ //whitelist
			$cached_whitelist[ip2long($ip)] = json_encode($list_data);
			update_option('tinyshield_cached_whitelist', $cached_whitelist);
			return false;
		}
	}

	private static function check_ip_whitelist($ip){
		$cached_whitelist = get_option('tinyshield_cached_whitelist');
		$cached_perm_whitelist = get_option('tinyshield_cached_perm_whitelist');

		if(is_array($cached_whitelist) && is_array($cached_perm_whitelist)){
			if(array_key_exists(ip2long($ip), $cached_perm_whitelist)){
				return true;
			}

			if(array_key_exists(ip2long($ip), $cached_whitelist)){
				$ip_meta = json_decode($cached_whitelist[ip2long($ip)]);
				if($ip_meta->expires >= time()){
					return true;
				}
			}
		}

		return false;
	}

	private static function clean_up_lists(){
		$cached_blacklist = get_option('tinyshield_cached_blacklist');
		$cached_whitelist = get_option('tinyshield_cached_whitelist');

		foreach($cached_blacklist as $iphash => $iphash_data){
			$iphash_data = json_decode($iphash_data);

			if($iphash_data->expires < time()){
				unset($cached_blacklist[$iphash]);
			}
		}

		foreach($cached_whitelist as $iphash => $iphash_data){
			$iphash_data = json_decode($iphash_data);

			if($iphash_data->expires < time()){
				unset($cached_whitelist[$iphash]);
			}
		}

		update_option('tinyshield_cached_whitelist', $cached_whitelist);
		update_option('tinyshield_cached_blacklist', $cached_blacklist);
	}

	private static function get_valid_ip(){
		if(filter_var($_SERVER['REMOTE_ADDR'], FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)){
			return $_SERVER['REMOTE_ADDR'];
		}

		return false;
	}

	private static function activate_site($key){
		$response = wp_remote_post(
			self::$tinyshield_activation_url,
			array(
				'body' => array(
					'activating_site' => site_url(),
					'activation_key' => esc_attr($key)
				)
			)
		);

		if(is_wp_error($response)){
			return false;
		}

		if($response['body'] == 'activated'){
			return true;
		}

		return sanitize_text_field($response['body']);
}

	public static function log_failed_login($username){
		$remote_ip = self::get_valid_ip();
		if($remote_ip){
			$report = self::report_failed_logins($remote_ip, $username, current_time('timestamp', true));
		}
	}

	private static function report_failed_logins($ip_to_report, $username_tried, $time){
		$response = wp_remote_post(
			self::$tinyshield_report_url,
			array(
				'body' => array(
					'ip_to_report' => $ip_to_report,
					'username_tried' => $username_tried,
					'reporting_site' => site_url(),
					'time_of_occurance' => $time
				)
			)
		);

		return $response;
	}

	public static function display_options(){
		$options = get_option('tinyshield_options');
		$cached_blacklist = get_option('tinyshield_cached_blacklist');
		$cached_whitelist = get_option('tinyshield_cached_whitelist');
		$cached_perm_whitelist = get_option('tinyshield_cached_perm_whitelist');

		/*
				Settings Page Update
		*/
		if(isset($_POST['tinyshield_save_options'])) {
			check_admin_referer('update-tinyshield-options');

			if(empty($options['site_activation_key']) && isset($_POST['site_activation_key'])){
				$maybe_activate = self::activate_site($_POST['site_activation_key']);

				if(is_bool($maybe_activate) && $maybe_activate){
					$options['site_activation_key'] = sanitize_text_field($_POST['site_activation_key']);
					update_option('tinyshield_options', $options);
?>
					<div class="updated"><p><strong><?php _e('Site Key Activated', 'tinyshield');?></strong></p></div>

<?php
				}else{
					$error_messages = array(
						'key_not_found' => 'Sorry, this key was not found. Please try again.',
						'key_in_use' => 'Sorry, this key is already in use. Please try again.',
						'key_expired' => 'This key is expired. Please renew your key.',
						'key_banned' => 'This key has been banned.'
					);
?>
					<div class="error"><p><strong><?php esc_attr_e($error_messages[$maybe_activate]); ?></strong></p></div>
<?php

				}
			}
		}

		/*****************************************
			Permanent Whitelist Custom Update Action
		******************************************/
		if(isset($_POST['tinyshield_perm_whitelist_update'])){
			check_admin_referer('update-tinyshield-perm-whitelist');

			if(empty($_POST['perm_ip_to_whitelist']) || !filter_var($_POST['perm_ip_to_whitelist'], FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)){
?>
				<div class="error"><p><strong><?php _e('Please enter a valid IP address.', "tinyshield");?></strong></p></div>
<?php
			}else{
				$perm_whitelist_entry = new stdClass();
				$perm_whitelist_entry->expires = strtotime('+30 years');

				$cached_perm_whitelist[ip2long($_POST['perm_ip_to_whitelist'])] = json_encode($perm_whitelist_entry);
				update_option('tinyshield_cached_perm_whitelist', $cached_perm_whitelist);
?>
				<div class="updated"><p><strong><?php _e('IP Address has been added to the Permanent Whitelist', "tinyshield");?></strong></p></div>
<?php
			}
		}

		/*****************************************
		 	Delete Perm Whitelist Action
		******************************************/
		if(isset($_GET['action']) && $_GET['action'] == 'delete-perm-whitelist' && is_numeric($_GET['iphash'])&& wp_verify_nonce($_GET['_wpnonce'], 'delete-tinyshield-perm-whitelist-item')){
			unset($cached_perm_whitelist[$_GET['iphash']]);
			update_option('tinyshield_cached_perm_whitelist', $cached_perm_whitelist);
?>
			<div class="updated"><p><strong><?php _e('IP Address has been removed from the Permanent Whitelist', "tinyshield");?></strong></p></div>
<?php
		}

		/*****************************************
		 	Move Whitelist to Blacklist Action
		******************************************/
		if(isset($_GET['action']) && $_GET['action'] == 'add_to_blacklist' && is_numeric($_GET['iphash'])&& wp_verify_nonce($_GET['_wpnonce'], 'tinyshield-move-item-blacklist')){
			$cached_blacklist[$_GET['iphash']] = strtotime('+24 hours');
			unset($cached_whitelist[$_GET['iphash']]);

			update_option('tinyshield_cached_whitelist', $cached_whitelist);
			update_option('tinyshield_cached_blacklist', $cached_blacklist);
?>
			<div class="updated"><p><strong><?php _e('The IP Address has been removed from the Blacklist and has been placed in the Permanent Whitelist.', "tinyshield");?></strong></p></div>
<?php
		}

		/*****************************************
		 	Move to Perm Whitelist Action
		******************************************/
		if(isset($_GET['action']) && $_GET['action'] == 'add_to_perm_whitelist' && is_numeric($_GET['iphash'])&& wp_verify_nonce($_GET['_wpnonce'], 'tinyshield-move-item-perm_whitelist')){
			$cached_perm_whitelist[$_GET['iphash']] = strtotime('+30 years');
			unset($cached_blacklist[$_GET['iphash']]);

			update_option('tinyshield_cached_perm_whitelist', $cached_perm_whitelist);
			update_option('tinyshield_cached_blacklist', $cached_blacklist);
?>
			<div class="updated"><p><strong><?php _e('The IP Address has been removed from the Blacklist and has been placed in the Permanent Whitelist.', "tinyshield");?></strong></p></div>
<?php
		}

		/*****************************************
			Delete IP Address from Blacklist Action
		******************************************/
		if(isset($_GET['action']) && $_GET['action'] == 'remove_from_blacklist' && is_numeric($_GET['iphash'])&& wp_verify_nonce($_GET['_wpnonce'], 'tinyshield-delete-blacklist-item')){
			unset($cached_blacklist[$_GET['iphash']]);
			update_option('tinyshield_cached_blacklist', $cached_blacklist);
?>
			<div class="updated"><p><strong><?php _e('The IP Address has been removed from the Blacklist. If this IP is trys to connect to your site again, it will be rechecked.', "tinyshield");?></strong></p></div>
<?php
		}

		/*****************************************
			Delete IP Address from Whitelist Action
		******************************************/
		if(isset($_GET['action']) && $_GET['action'] == 'remove_from_whitelist' && is_numeric($_GET['iphash'])&& wp_verify_nonce($_GET['_wpnonce'], 'tinyshield-delete-whitelist-item')){
			unset($cached_whitelist[$_GET['iphash']]);
			update_option('tinyshield_cached_whitelist', $cached_whitelist);
?>
			<div class="updated"><p><strong><?php _e('The IP Address has been removed from the Blacklist. If this IP is trys to connect to your site again, it will be rechecked.', "tinyshield");?></strong></p></div>
<?php
		}
?>
			<div class="wrap">
				<?php $active_tab = isset( $_GET[ 'tab' ] ) ? $_GET[ 'tab' ] : 'settings'; ?>
				<h2> <?php _e('tinyShield - Simple. Focused. Security.', 'tinyshield') ?></h2>
				<h2 class="nav-tab-wrapper">
					<a href="?page=tinyshield.php&tab=settings" class="nav-tab <?php echo $active_tab == 'settings' ? 'nav-tab-active' : ''; ?>">Settings</a>
					<a href="?page=tinyshield.php&tab=perm-whitelist" class="nav-tab <?php echo $active_tab == 'perm-whitelist' ? 'nav-tab-active' : ''; ?>">Permanent Whitelist (<?php echo count($cached_perm_whitelist); ?>)</a>
					<a href="?page=tinyshield.php&tab=whitelist" class="nav-tab <?php echo $active_tab == 'whitelist' ? 'nav-tab-active' : ''; ?>">Whitelist (<?php echo count($cached_whitelist); ?>)</a>
					<a href="?page=tinyshield.php&tab=blacklist" class="nav-tab <?php echo $active_tab == 'blacklist' ? 'nav-tab-active' : ''; ?>">Blacklist (<?php echo count($cached_blacklist); ?>)</a>
				</h2>

				<?php if($active_tab == 'settings'): ?>
					<form method="post" action="<?php echo esc_attr($_SERVER["REQUEST_URI"]); ?>">
						<?php
							if(function_exists('wp_nonce_field')){
								wp_nonce_field('update-tinyshield-options');
							}
						?>

						<h3><?php _e('Activation Key', 'tinyshield') ?></h3>
						<p>Each site using this plugin is required to have an activation key. For a key, visit <a target="_blank" href="<?php echo esc_attr(self::$tinyshield_signup_url); ?>"><?php echo esc_attr(self::$tinyshield_signup_url); ?></a></p>
						<p><input type="text" name="site_activation_key" size="24" value="<?php echo esc_attr($options['site_activation_key']); ?>"></p>

						<div class="submit">
							<input type="submit" class="button button-primary" name="tinyshield_save_options" value="<?php _e('Save Settings', 'tinyshield') ?>" />
						</div>
					</form>
				<?php endif; ?>
				<?php if($active_tab == 'perm-whitelist'): ?>
					<form method="post" action="<?php echo esc_attr($_SERVER['REQUEST_URI']); ?>">
						<?php
							if(function_exists('wp_nonce_field')){
								wp_nonce_field('update-tinyshield-perm-whitelist');
								$delete_item_nonce = wp_create_nonce('delete-tinyshield-perm-whitelist-item');
							}
						?>
						<h3>Permanent Whitelist</h3>
						<p>These are addresses that are permanently allowed to access the site even if they are found in a black list. This is useful for false positives. The permanent whitelist is checked before any other check is performed.</p>
						<hr />
						<p><input type="text" name="perm_ip_to_whitelist" size="36" placeholder="<?php _e('Enter a valid single IP Address...', 'tinyshield'); ?>" value=""> <input type="submit" class="button button-primary" name="tinyshield_perm_whitelist_update" value="<?php _e('Save Whitelist', 'tinyshield') ?>" /></p>
					</form>
					<?php
						$tinyShield_PermWhiteList_Table = new tinyShield_PermWhiteList_Table();
						$tinyShield_PermWhiteList_Table->prepare_items();
					?>
					<form id="perm-whitelist-table" method="get">
						<input type="hidden" name="page" value="<?php echo absint($_REQUEST['page']); ?>" />
						<?php $tinyShield_PermWhiteList_Table->display(); ?>
					</form>
			  <?php endif; ?>
				<?php if($active_tab == 'whitelist'): ?>
					<h3>Whitelist</h3>
					<p>These are addresses that have been checked and are not known to be malicious at this time. Addresses will remain cached for 24 hours and then will be checked again.</p>
					<hr />
					<?php
						$tinyShield_WhiteList_Table = new tinyShield_WhiteList_Table();
						$tinyShield_WhiteList_Table->prepare_items();
					?>
					<form id="whitelist-table" method="get">
						<input type="hidden" name="page" value="<?php echo absint($_REQUEST['page']); ?>" />
						<?php $tinyShield_WhiteList_Table->display(); ?>
					</form>
			  <?php endif; ?>
				<?php if($active_tab == 'blacklist'): ?>
					<h3>Blacklist</h3>
					<p>These are addresses that have tried to visit your site and been found to be malicious. Requests from these addresses are blocked and will remain cached for 24 hours and then will be checked again.</p>
					<hr />
					<?php
						$tinyShield_BlackList_Table = new tinyShield_BlackList_Table();
						$tinyShield_BlackList_Table->prepare_items();
					?>
					<form id="blacklist-table" method="get">
						<input type="hidden" name="page" value="<?php echo absint($_REQUEST['page']); ?>" />
						<?php $tinyShield_BlackList_Table->display(); ?>
					</form>
				<?php endif; ?>

			</div> <!--end div -->
<?php
	}
} //End tinyShield Class

$tinyShield = new tinyShield();
