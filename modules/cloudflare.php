<?php

  add_action('tinyshield_block_ip', 'tinyShield_Module_CloudFlare::create_access_rule');
  add_action('tinyshield_blocklist_clear_ip', 'tinyShield_Module_CloudFlare::clean_up');

  class tinyShield_Module_CloudFlare extends tinyShield{

    public static function create_access_rule($data){
      $options = get_option('tinyshield_options');

      if($options['cloudflare_enabled'] && !empty($options['cloudflare_email']) && !empty($options['cloudflare_auth_key']) && !empty($options['cloudflare_zone_id']) && is_object($data) && !empty($data->ip_address)){
        self::write_log('tinyShield: create_access_rule');

        $response = wp_remote_post(
          'https://api.cloudflare.com/client/v4/zones/' . $options['cloudflare_zone_id'] . '/firewall/access_rules/rules',
          array(
            'headers' => array(
              'X-Auth-Email' => $options['cloudflare_email'],
              'X-Auth-Key' => $options['cloudflare_auth_key'],
              'Content-Type' => 'application/json'
            ),
            'body' => wp_json_encode(
              array(
                'mode' => 'challenge',
                'configuration' => array(
                  'target' => 'ip',
                  'value' => $data->ip_address
                ),
                'notes' => 'Blocked by tinyShield on ' . current_time('mysql')
              )
            )
          )
        );

        if(!is_wp_error($response) && wp_remote_retrieve_response_code($response) == 200){
          $return = json_decode(wp_remote_retrieve_body($response));

          if($return->success){

            if(empty($options['cloudflare_ips'])){
              $options['cloudflare_ips'] = serialize(array(
                sha1($data->ip_address) => $return->result->id
              ));
            }else{
                $cloudflare_ips = unserialize($options['cloudflare_ips']);

                if(is_array($cloudflare_ips)){
                  $options['cloudflare_ips'] = serialize(array_merge($cloudflare_ips, array(
                    sha1($data->ip_address) => $return->result->id
                  )));
                }
            }

            update_option('tinyshield_options', $options);

            self::write_log('tinyShield: cloudflare acceess rule created successfully with id ' . $return->result->id);
            return true;
          }

        }else{
          if(is_wp_error($response)){
            self::write_log('tinyShield: cloudflare remote post error ' . $response->get_error_message());
          }else{
            self::write_log('tinyShield: cloudflare http status code ' . wp_remote_retrieve_response_code($response));

            $return = json_decode(wp_remote_retrieve_body($response));
            if(is_object($return) && $return->success === false){
              $error = $return->errors[0];
              self::write_log('tinyShield: cloudflare error code: ' . $error->code . ' message: ' . $error->message);
            }
          }
          return false;
        }
      }
    }

    public static function clean_up($iphash){
      $options = get_option('tinyshield_options');
      $cloudflare_ips = unserialize($options['cloudflare_ips']);

      if(!empty($options['cloudflare_email']) && !empty($options['cloudflare_auth_key']) && !empty($options['cloudflare_zone_id']) && array_key_exists($iphash, $cloudflare_ips)){
        self::write_log('tinyShield: cloudflare cleanup');

        $response = wp_remote_request(
          'https://api.cloudflare.com/client/v4/zones/' . $options['cloudflare_zone_id'] . '/firewall/access_rules/rules/' . $cloudflare_ips[$iphash],
          array(
            'method' => 'DELETE',
            'headers' => array(
              'X-Auth-Email' => $options['cloudflare_email'],
              'X-Auth-Key' => $options['cloudflare_auth_key'],
              'Content-Type' => 'application/json'
            ),
          )
        );

        if(!is_wp_error($response) && wp_remote_retrieve_response_code($response) == 200){
          $return = json_decode(wp_remote_retrieve_body($response));

          if($return->success){
            self::write_log('tinyShield: cloudflare acceess rule deleted successfully with id ' . $iphash);
            unset($cloudflare_ips[$iphash]);

            $options['cloudflare_ips'] = serialize($cloudflare_ips);
            update_option('tinyshield_options', $options);

            return true;
          }
        }elseif(is_wp_error($response)){
          self::write_log('tinyShield: cloudflare remote post error ' . $response->get_error_message());
        }
      }

      return false;
    }
  }
