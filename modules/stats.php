<?php

  add_action('tinyshield_block_ip', 'tinyShield_Module_Stats::add_stats');
  add_action('tinyshield_allow_ip', 'tinyShield_Module_Stats::add_stats');

  class tinyShield_Module_Stats extends tinyShield{

    public static function add_stats($data){
      $options = get_option('tinyshield_options');
      self::write_log('tinyShield: stats initiated - ' . $data->ip_address);

      if(empty($options['tinyshield_stats'])){
        if($data->action == 'allow'){
          self::write_log('tinyShield: stats blank - creating allowed ' . $data->ip_address);
          $options['tinyshield_stats'] = serialize(
            array('allowed' => array(
              strtotime('today') => 1,
            )
          ));
        }elseif($data->action == 'block'){
          self::write_log('tinyShield: stats blank - creating blocked ' . $data->ip_address);
          $options['tinyshield_stats'] = serialize(
            array('blocked' => array(
              strtotime('today') => 1,
            )
          ));
        }

        update_option('tinyshield_options', $options);
      }else{
        $stats = unserialize($options['tinyshield_stats']);

        if(is_array($stats) && is_object($data)){
          if($data->action == 'allow'){
            self::write_log('tinyShield: adding one point to allowed stats ' . $data->ip_address);
            $stats['allowed'][strtotime('today')]++;
          }elseif($data->action == 'block'){
            self::write_log('tinyShield: adding one point to blocked stats ' . $data->ip_address);
            $stats['blocked'][strtotime('today')]++;
          }
        }

        $options['tinyshield_stats'] = serialize($stats);
        update_option('tinyshield_options', $options);
      }

      return true;
    }
  }
