<?php
  class tinyShieldUpgradeFunctions extends tinyShield{

    public static function upgrade_03_to_04(){
      $cached_blacklist = get_option('tinyshield_cached_blacklist');
      $cached_whitelist = get_option('tinyshield_cached_whitelist');
      $cached_perm_whitelist = get_option('tinyshield_cached_perm_whitelist');
      $cached_perm_blacklist = get_option('tinyshield_cached_perm_blacklist');

      //update cached allow and block lists
      update_option('tinyshield_cached_blacklist', array());
      update_option('tinyshield_cached_whitelist', array());

      //upgrade permanent lists
      if(is_array($cached_perm_blacklist) && !empty($cached_perm_blacklist)){
        $updated_array = array();

        foreach($cached_perm_blacklist as $key => $entry){
          if(is_int($key)){
            $ip = long2ip($key);
            $meta = json_decode($entry);

            if(is_object($meta)){
              $meta->ip_address = $ip;
              $updated_array[sha1($ip)] = json_encode($meta);
            }
          }
        }

        update_option('tinyshield_cached_perm_blacklist', $updated_array);
      }

      if(is_array($cached_perm_whitelist) && !empty($cached_perm_whitlist)){
        $updated_array = array();

        foreach($cached_perm_whitelist as $key => $entry){
          if(is_int($key)){
            $ip = long2ip($key);
            $meta = json_decode($entry);

            if(is_object($meta)){
              $meta->ip_address = $ip;
              $updated_array[sha1($ip)] = json_encode($meta);
            }
          }
        }

        update_option('tinyshield_cached_perm_whitelist', $updated_array);
      }

      if(!is_array($cached_perm_blacklist)){
        $cached_perm_blacklist = array();
        update_option('tinyshield_cached_perm_blacklist', $cached_perm_blacklist);
      }
    }

    public static function upgrade_040_to_055(){
      $cached_blacklist = get_option('tinyshield_cached_blacklist');
      $cached_whitelist = get_option('tinyshield_cached_whitelist');
      $cached_perm_whitelist = get_option('tinyshield_cached_perm_whitelist');
      $cached_perm_blacklist = get_option('tinyshield_cached_perm_blacklist');

      if($cached_blacklist !== false){
        update_option('tinyshield_cached_blocklist', $cached_blacklist);
        delete_option('tinyshield_cached_blacklist');
      }

      if($cached_whitelist !== false){
        update_option('tinyshield_cached_allowlist', $cached_whitelist);
        delete_option('tinyshield_cached_whitelist');
      }

      if($cached_perm_whitelist !== false){
        update_option('tinyshield_cached_perm_allowlist', $cached_perm_whitelist);
        delete_option('tinyshield_cached_perm_whitelist');
      }

      if($cached_perm_blacklist !== false){
        update_option('tinyshield_cached_perm_blocklist', $cached_perm_blacklist);
        delete_option('tinyshield_cached_perm_blacklist');
      }
    }
  }
