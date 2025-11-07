<?php
/**
 * Plugin Name: SSL Expiry Manager (All-in-One + Front Controls + Token Page)
 * Description: ניהול ובדיקת תוקף SSL בטבלה עם עריכה, ייבוא/ייצוא CSV, סל מחזור 90 יום, REST לסוכן מקומי, בקרות פרונט ועמוד ניהול טוקן.
 * Version: 1.5.0
 * Author: Ofri + GPT
 */
 
 add_filter('rest_authentication_errors', function($result){
    $route = $_GET['rest_route'] ?? ($_SERVER['REQUEST_URI'] ?? '');
    if (strpos($route, '/ssl-agent/v1/') === false) return $result;

    $hdr = $_SERVER['HTTP_X_AGENT_TOKEN'] ?? '';
    $tok = get_option('ssl_agent_token', '');
    if ($tok && hash_equals($tok, $hdr)) return true;

    return new WP_Error('forbidden','bad token',['status'=>403]);
}, 0);

if (!defined('ABSPATH')) exit;

if (!class_exists('SSL_Expiry_Manager_AIO')) {
class SSL_Expiry_Manager_AIO {
    const CPT = 'ssl_cert';
    const TABLE = 'ssl_em_certificates';
    const CRON_HOOK = 'ssl_expiry_manager_daily_check';
    const NONCE = 'ssl_expiry_manager_nonce';
    const EXPORT_ACTION = 'ssl_expiry_export';
    const IMPORT_ACTION = 'ssl_expiry_import';
    const SAVE_ACTION   = 'ssl_expiry_save';
    const DELETE_ACTION = 'ssl_expiry_delete';
    const RESTORE_ACTION= 'ssl_expiry_restore';
    const OPTION_TOKEN  = 'ssl_em_api_token';
    const OPTION_REMOTE = 'ssl_em_remote_client';
    const OPTION_QUEUE  = 'ssl_em_task_queue';
    const OPTION_LOG    = 'ssl_em_activity_log';
    const OPTION_SQL_SEEDED = 'ssl_em_sql_seeded';
    const QUEUE_CLAIM_TTL = 300; // 5 minutes
    const ADD_TOKEN_ACTION    = 'ssl_add_token';
    const MANAGE_TOKEN_ACTION = 'ssl_manage_token';
    const PAGE_MAIN_FALLBACK  = 'https://kbtest.macomp.co.il/?p=9427';
    const PAGE_TRASH_FALLBACK = 'https://kbtest.macomp.co.il/?p=9441';
    const PAGE_TOKEN_FALLBACK = 'https://kbtest.macomp.co.il/?p=9447';
    const PAGE_LOG_FALLBACK   = 'https://kbtest.macomp.co.il/?p=9458';

    public function __construct() {
        add_action('init', [$this,'register_cpt']);
        add_action('init', [$this,'register_meta']);
        add_action('init', [$this,'ensure_sql_table']);
        add_shortcode('ssl_cert_table', [$this,'shortcode_table']);
        add_shortcode('ssl_trash',      [$this,'shortcode_trash']);
        add_shortcode('ssl_controls',   [$this,'shortcode_controls']);
        add_shortcode('ssl_token',      [$this,'shortcode_token']);
        add_shortcode('ssl_token_page', [$this,'shortcode_token_page']); // חדש
        add_shortcode('ssl_logs',       [$this,'shortcode_logs']);
        add_action('wp_enqueue_scripts', [$this,'assets']);

        add_action('admin_post_nopriv_'.self::SAVE_ACTION,    [$this,'handle_save']);
        add_action('admin_post_'.self::SAVE_ACTION,           [$this,'handle_save']);
        add_action('admin_post_nopriv_'.self::DELETE_ACTION,  [$this,'handle_delete']);
        add_action('admin_post_'.self::DELETE_ACTION,         [$this,'handle_delete']);
        add_action('admin_post_nopriv_'.self::RESTORE_ACTION, [$this,'handle_restore']);
        add_action('admin_post_'.self::RESTORE_ACTION,        [$this,'handle_restore']);
        add_action('admin_post_nopriv_'.self::EXPORT_ACTION,  [$this,'handle_export']);
        add_action('admin_post_'.self::EXPORT_ACTION,         [$this,'handle_export']);
        add_action('admin_post_nopriv_'.self::IMPORT_ACTION,  [$this,'handle_import']);
        add_action('admin_post_'.self::IMPORT_ACTION,         [$this,'handle_import']);
        add_action('admin_post_nopriv_ssl_regen_token',       [$this,'handle_regen_token']);
        add_action('admin_post_ssl_regen_token',              [$this,'handle_regen_token']);
        add_action('admin_post_nopriv_'.self::ADD_TOKEN_ACTION,    [$this,'handle_add_token']);
        add_action('admin_post_'.self::ADD_TOKEN_ACTION,            [$this,'handle_add_token']);
        add_action('admin_post_nopriv_'.self::MANAGE_TOKEN_ACTION, [$this,'handle_manage_token']);
        add_action('admin_post_'.self::MANAGE_TOKEN_ACTION,        [$this,'handle_manage_token']);
        add_action('admin_post_ssl_save_remote_client',            [$this,'handle_save_remote_client']);

        add_action('wp', [$this,'ensure_cron']);
        add_action(self::CRON_HOOK, [$this,'cron_check_all']);

        add_filter('empty_trash_days', function(){ return 90; });
        add_action('init', function(){ if(!function_exists('wp_handle_upload')) require_once(ABSPATH.'wp-admin/includes/file.php'); });
        add_action('init', [$this,'ensure_token_store']);
        add_action('init', [$this,'ensure_queue_store']);
        add_action('init', [$this,'ensure_log_store']);
        add_action('init', [$this,'maybe_seed_sql_table']);

        add_action('rest_api_init', [$this,'register_rest']);
        add_action('admin_menu',    [$this,'settings_page']);
        register_activation_hook(__FILE__, [$this,'on_activate']);
        add_action('init', [$this,'route_export_helper']);

        add_action('save_post_'.self::CPT, [$this,'hook_sync_post'], 10, 3);
        add_action('trashed_post', [$this,'hook_trash_post']);
        add_action('untrashed_post', [$this,'hook_untrash_post']);
        add_action('before_delete_post', [$this,'hook_delete_post']);
    }

    public function register_cpt() {
        register_post_type(self::CPT, [
            'label' => 'SSL Certificates',
            'public' => false,
            'show_ui' => true,
            'supports' => ['title'],
            'capability_type' => 'post',
            'map_meta_cap' => true,
            'show_in_rest' => false,
        ]);
    }
    public function register_meta() {
        $fields = [
            'client_name'=>'string','site_url'=>'string','expiry_ts'=>'integer','source'=>'string',
            'notes'=>'string','images'=>'array','last_error'=>'string','expiry_ts_checked_at'=>'integer','agent_only'=>'boolean',
            'cert_cn'=>'string'
        ];
        foreach ($fields as $k=>$t){
            register_post_meta(self::CPT,$k,[
                'type'=> $t==='array'?'array':$t,'single'=>true,'show_in_rest'=>false,'auth_callback'=>'__return_true',
            ]);
        }
    }

    private function get_table_name(){
        global $wpdb;
        return $wpdb->prefix . self::TABLE;
    }

    public function ensure_sql_table(){
        global $wpdb;
        $table = $this->get_table_name();
        $charset = $wpdb->get_charset_collate();
        require_once ABSPATH . 'wp-admin/includes/upgrade.php';
        $sql = "CREATE TABLE {$table} (
            id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
            post_id BIGINT UNSIGNED NOT NULL,
            status VARCHAR(20) NOT NULL DEFAULT 'publish',
            client_name VARCHAR(255) NOT NULL DEFAULT '',
            site_url TEXT,
            common_name VARCHAR(255) NOT NULL DEFAULT '',
            expiry_ts BIGINT NULL,
            source VARCHAR(50) NOT NULL DEFAULT '',
            notes LONGTEXT,
            agent_only TINYINT(1) NOT NULL DEFAULT 0,
            last_error LONGTEXT,
            expiry_ts_checked_at BIGINT NULL,
            images LONGTEXT,
            created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
            PRIMARY KEY (id),
            UNIQUE KEY post_id (post_id),
            KEY status (status),
            KEY cn_status (common_name(190), status),
            KEY site_url (site_url(190))
        ) {$charset};";
        dbDelta($sql);
    }

    public function maybe_seed_sql_table(){
        if(get_option(self::OPTION_SQL_SEEDED)){
            return;
        }
        $this->sync_all_posts_to_table();
        update_option(self::OPTION_SQL_SEEDED, time(), false);
    }

    private function sync_all_posts_to_table(){
        $q = new WP_Query([
            'post_type'      => self::CPT,
            'post_status'    => ['publish','draft','pending','trash'],
            'posts_per_page' => -1,
        ]);
        if($q->have_posts()){
            while($q->have_posts()){
                $q->the_post();
                $post = get_post();
                if($post){
                    $this->sync_table_record($post->ID, $post->post_status);
                }
            }
            wp_reset_postdata();
        }
    }

    public function hook_sync_post($post_id, $post, $update){
        if(!$post || $post->post_type !== self::CPT){
            return;
        }
        if(defined('DOING_AUTOSAVE') && DOING_AUTOSAVE){
            return;
        }
        if(wp_is_post_revision($post_id)){
            return;
        }
        $this->sync_table_record($post_id, $post->post_status);
    }

    public function hook_trash_post($post_id){
        $post = get_post($post_id);
        if(!$post || $post->post_type !== self::CPT){
            return;
        }
        $this->update_table_status($post_id, 'trash');
    }

    public function hook_untrash_post($post_id){
        $post = get_post($post_id);
        if(!$post || $post->post_type !== self::CPT){
            return;
        }
        $this->update_table_status($post_id, $post->post_status ?: 'publish');
    }

    public function hook_delete_post($post_id){
        $post = get_post($post_id);
        if(!$post || $post->post_type !== self::CPT){
            return;
        }
        $this->delete_table_record($post_id);
    }

    private function update_table_status($post_id, $status){
        global $wpdb;
        $table = $this->get_table_name();
        $wpdb->update($table, ['status' => sanitize_key($status)], ['post_id' => (int)$post_id]);
    }

    private function sync_table_record($post_id, $status = null){
        $post = get_post($post_id);
        if(!$post || $post->post_type !== self::CPT){
            return;
        }
        $status = $status ?: $post->post_status;
        $client = (string)get_post_meta($post_id,'client_name',true);
        $site = (string)get_post_meta($post_id,'site_url',true);
        $expiry = get_post_meta($post_id,'expiry_ts',true);
        $source = (string)get_post_meta($post_id,'source',true);
        $notes = (string)get_post_meta($post_id,'notes',true);
        $agent_only = (int)get_post_meta($post_id,'agent_only',true);
        $last_error = (string)get_post_meta($post_id,'last_error',true);
        $checked = get_post_meta($post_id,'expiry_ts_checked_at',true);
        $images = get_post_meta($post_id,'images',true);
        $cn = (string)get_post_meta($post_id,'cert_cn',true);
        if(!is_array($images)){
            $images = [];
        }
        $image_ids = array_map('intval', $images);
        global $wpdb;
        $table = $this->get_table_name();
        $images_json = wp_json_encode($image_ids);
        if($images_json === false){
            $images_json = '[]';
        }
        $data = [
            'post_id' => (int)$post_id,
            'status' => sanitize_key($status ?: 'publish'),
            'client_name' => wp_strip_all_tags($client),
            'site_url' => esc_url_raw($site),
            'common_name' => wp_strip_all_tags($cn),
            'expiry_ts' => $expiry ? (int)$expiry : null,
            'source' => $this->normalize_source_value($source, 'manual'),
            'notes' => $notes,
            'agent_only' => $agent_only ? 1 : 0,
            'last_error' => $last_error,
            'expiry_ts_checked_at' => $checked ? (int)$checked : null,
            'images' => $images_json,
        ];
        $formats = ['%d','%s','%s','%s','%s','%d','%s','%s','%d','%s','%d','%s'];
        $existing = $wpdb->get_var($wpdb->prepare("SELECT id FROM {$table} WHERE post_id = %d", $post_id));
        if($existing){
            $wpdb->update($table, $data, ['post_id' => (int)$post_id], $formats, ['%d']);
        } else {
            $wpdb->insert($table, $data, $formats);
        }
        if(!$expiry){
            $wpdb->query($wpdb->prepare("UPDATE {$table} SET expiry_ts = NULL WHERE post_id = %d", $post_id));
        }
        if(!$checked){
            $wpdb->query($wpdb->prepare("UPDATE {$table} SET expiry_ts_checked_at = NULL WHERE post_id = %d", $post_id));
        }
    }

    private function delete_table_record($post_id){
        global $wpdb;
        $table = $this->get_table_name();
        $wpdb->delete($table, ['post_id' => (int)$post_id], ['%d']);
    }

    private function fetch_certificates($args = []){
        global $wpdb;
        $defaults = [
            'page' => 1,
            'per_page' => 25,
            'search' => '',
            'source' => '',
            'agent_only' => '',
            'status' => ['publish','draft','pending'],
            'orderby' => 'client_name',
            'order' => 'ASC',
        ];
        $args = wp_parse_args($args, $defaults);
        $table = $this->get_table_name();
        $where = ['1=1'];
        $params = [];
        $statuses = array_filter((array)$args['status']);
        if(empty($statuses)){
            $statuses = ['publish'];
        }
        $placeholders = implode(',', array_fill(0, count($statuses), '%s'));
        $where[] = "status IN ({$placeholders})";
        $params = array_merge($params, array_map('sanitize_key', $statuses));

        if($args['search'] !== ''){
            $search = '%' . $wpdb->esc_like($args['search']) . '%';
            $where[] = "(client_name LIKE %s OR site_url LIKE %s OR common_name LIKE %s)";
            $params[] = $search;
            $params[] = $search;
            $params[] = $search;
        }
        $requested_source = $this->normalize_source_value($args['source'] ?? '', '');
        if($requested_source !== ''){
            $where[] = "source = %s";
            $params[] = $requested_source;
        }
        if($args['agent_only'] !== ''){
            if($args['agent_only'] === '1'){
                $where[] = "agent_only = 1";
            } elseif($args['agent_only'] === '0'){
                $where[] = "agent_only = 0";
            }
        }
        $order = strtoupper($args['order']) === 'DESC' ? 'DESC' : 'ASC';
        $allowed_orderby = [
            'client_name' => 'client_name',
            'site_url' => 'site_url',
            'expiry_ts' => 'expiry_ts',
            'source' => 'source',
            'common_name' => 'common_name',
            'agent_only' => 'agent_only',
        ];
        $orderby = isset($allowed_orderby[$args['orderby']]) ? $allowed_orderby[$args['orderby']] : 'client_name';
        $where_sql = 'WHERE ' . implode(' AND ', $where);
        $limit = max(1, (int)$args['per_page']);
        $offset = max(0, ((int)$args['page'] - 1) * $limit);
        $order_sql = "ORDER BY {$orderby} {$order}, client_name ASC";
        $limit_sql = "LIMIT %d OFFSET %d";
        $rows_sql = "SELECT * FROM {$table} {$where_sql} {$order_sql} {$limit_sql}";
        $rows_params = array_merge($params, [$limit, $offset]);
        $count_sql = "SELECT COUNT(*) FROM {$table} {$where_sql}";
        $prepared_rows = $wpdb->prepare($rows_sql, $rows_params);
        $rows = $wpdb->get_results($prepared_rows, ARRAY_A);
        if(!empty($params)){
            $total = $wpdb->get_var($wpdb->prepare($count_sql, $params));
        } else {
            $total = $wpdb->get_var($count_sql);
        }
        foreach($rows as &$row){
            $row['agent_only'] = !empty($row['agent_only']);
            $row['images'] = $row['images'] ? json_decode($row['images'], true) : [];
            if(!is_array($row['images'])){
                $row['images'] = [];
            }
        }
        return [
            'rows' => $rows,
            'total' => (int)$total,
        ];
    }

    private function build_sort_link($column, $label, $current_sort, $current_order, $preserved_query){
        $column = sanitize_key($column);
        $current_sort = sanitize_key($current_sort);
        $current_order = strtoupper($current_order) === 'DESC' ? 'DESC' : 'ASC';
        $next_order = ($current_sort === $column && $current_order === 'ASC') ? 'DESC' : 'ASC';
        $query = $preserved_query;
        $query['ssl_sort'] = $column;
        $query['ssl_order'] = $next_order;
        $url = esc_url(add_query_arg($query));
        $indicator = '';
        if($current_sort === $column){
            $indicator = $current_order === 'ASC' ? ' ↑' : ' ↓';
        }
        return '<a href="'.$url.'" class="ssl-sort-link" data-ssl-sort="'.esc_attr($column).'" data-ssl-next-order="'.esc_attr(strtolower($next_order)).'">'.esc_html($label.$indicator).'</a>';
    }

    private function parse_import_file($file_path, $file_name){
        $ext = strtolower(pathinfo($file_name, PATHINFO_EXTENSION));
        if($ext === 'xlsx'){
            if(!class_exists('SimpleXLSX')){
                require_once __DIR__.'/simple_xlsx.php';
            }
            $xlsx = SimpleXLSX::parse($file_path);
            if(!$xlsx){
                return new WP_Error('import_parse', SimpleXLSX::parseError() ?: 'Excel parsing error');
            }
            $raw_rows = $xlsx->rows();
        } else {
            $raw_rows = $this->read_csv_rows($file_path);
        }
        if(empty($raw_rows)){
            return [];
        }
        return $this->normalize_import_rows($raw_rows);
    }

    private function read_csv_rows($file_path){
        $rows = [];
        $contents = file_get_contents($file_path);
        if($contents === false){
            return $rows;
        }
        $encoding = function_exists('mb_detect_encoding') ? mb_detect_encoding($contents, ['UTF-8','UTF-16','UTF-16LE','UTF-16BE','Windows-1255','ISO-8859-8','Windows-1252'], true) : false;
        if($encoding && strtoupper($encoding) !== 'UTF-8' && function_exists('mb_convert_encoding')){
            $contents = mb_convert_encoding($contents, 'UTF-8', $encoding);
        }
        if(strpos($contents, "\xEF\xBB\xBF") === 0){
            $contents = substr($contents, 3);
        }
        $stream = fopen('php://temp', 'r+');
        fwrite($stream, $contents);
        rewind($stream);
        while(($line = fgetcsv($stream)) !== false){
            $rows[] = $line;
        }
        fclose($stream);
        return $rows;
    }

    private function normalize_import_rows($rows){
        $normalized = [];
        if(empty($rows)){
            return $normalized;
        }
        $header_map = $this->map_import_header($rows[0]);
        if($header_map){
            array_shift($rows);
        } else {
            $first = isset($rows[0]) && is_array($rows[0]) ? $rows[0] : [];
            $count = count($first);
            if($count >= 8){
                $header_map = [
                    'client_name' => 0,
                    'site_url' => 1,
                    'expiry_date' => 2,
                    'common_name' => 3,
                    'source' => 4,
                    'notes' => 5,
                    'agent_only' => 7,
                ];
            } else {
                $header_map = [
                    'client_name' => 0,
                    'site_url' => 1,
                    'expiry_date' => 2,
                    'source' => 3,
                    'notes' => 4,
                ];
                if($count >= 7){
                    $header_map['agent_only'] = 6;
                } elseif($count >= 6){
                    $header_map['agent_only'] = 5;
                }
            }
        }
        foreach($rows as $row){
            if(!is_array($row)){
                continue;
            }
            $flat = array_map(function($value){
                return trim((string)$value);
            }, $row);
            $is_empty = true;
            foreach($flat as $value){
                if($value !== ''){
                    $is_empty = false;
                    break;
                }
            }
            if($is_empty){
                continue;
            }
            $client = $this->value_from_row($flat, $header_map, 'client_name');
            $site = $this->value_from_row($flat, $header_map, 'site_url');
            $expiry_raw = $this->value_from_row($flat, $header_map, 'expiry_date');
            $cn = $this->value_from_row($flat, $header_map, 'common_name');
            $source_raw = $this->value_from_row($flat, $header_map, 'source');
            $notes = $this->value_from_row($flat, $header_map, 'notes');
            $agent_raw = $this->value_from_row($flat, $header_map, 'agent_only');
            $date_norm = $this->normalize_import_date($expiry_raw);
            $expiry_ts = $date_norm ? strtotime($date_norm.' 00:00:00') : null;
            $normalized[] = [
                'client_name' => wp_strip_all_tags($client),
                'site_url' => $this->sanitize_url($site),
                'expiry_date' => $date_norm,
                'expiry_ts' => $expiry_ts ?: null,
                'common_name' => wp_strip_all_tags($cn),
                'source' => $this->normalize_import_source($source_raw),
                'notes' => sanitize_textarea_field($notes),
                'agent_only' => $this->interpret_bool($agent_raw),
            ];
        }
        return $normalized;
    }

    private function map_import_header($header_row){
        if(empty($header_row) || !is_array($header_row)){
            return null;
        }
        $normalized = [];
        foreach($header_row as $index => $value){
            $label = $this->lower((string)$value);
            if($label !== ''){
                $normalized[$label] = $index;
            }
        }
        $aliases = [
            'client_name' => ['client_name','שם הלקוח','לקוח'],
            'site_url' => ['site_url','url','כתובת','אתר'],
            'expiry_date' => ['expiry_date','expiry','תוקף','תאריך תפוגה'],
            'common_name' => ['common_name','cn','שם תעודה'],
            'source' => ['source','מקור','ליקוט'],
            'notes' => ['notes','הערות'],
            'agent_only' => ['agent_only','agent','סוכן','agent only'],
        ];
        $map = [];
        foreach($aliases as $field => $options){
            foreach($options as $alias){
                $alias_key = $this->lower($alias);
                if(isset($normalized[$alias_key])){
                    $map[$field] = $normalized[$alias_key];
                    break;
                }
            }
        }
        if(isset($map['client_name']) && isset($map['site_url'])){
            return $map;
        }
        return null;
    }

    private function value_from_row($row, $map, $field){
        if(isset($map[$field]) && isset($row[$map[$field]])){
            return $row[$map[$field]];
        }
        return '';
    }

    private function normalize_import_date($value){
        $value = trim((string)$value);
        if($value === ''){
            return '';
        }
        if(preg_match('/^\d{4}-\d{2}-\d{2}$/', $value)){
            return $value;
        }
        $ts = strtotime($value);
        if($ts){
            return gmdate('Y-m-d', $ts);
        }
        return '';
    }

    private function normalize_import_source($value){
        $value = $this->lower($value);
        if(in_array($value, ['agent','סוכן'], true)){
            $normalized = 'agent';
        } elseif(in_array($value, ['auto','automatic','אוטומטי'], true)){
            $normalized = 'auto';
        } else {
            $normalized = 'manual';
        }
        return $this->normalize_source_value($normalized, 'manual');
    }

    private function normalize_source_value($value, $default = 'auto'){
        $value = sanitize_key((string)$value);
        if(in_array($value, ['auto','manual','agent'], true)){
            return $value;
        }
        return $default;
    }

    private function interpret_bool($value){
        $value = $this->lower($value);
        if($value === ''){
            return false;
        }
        return in_array($value, ['1','true','yes','y','on','כן','חיובי'], true);
    }

    private function lower($value){
        $value = trim((string)$value);
        if($value === ''){
            return '';
        }
        if(function_exists('mb_strtolower')){
            return mb_strtolower($value, 'UTF-8');
        }
        return strtolower($value);
    }

    public function assets() {
        $css = <<<'CSS'
.ssl-manager{direction:rtl;font-family:"Assistant","Rubik",Arial,sans-serif;background:#fff;border-radius:16px;box-shadow:0 12px 30px rgba(15,23,42,.08);padding:24px;margin:24px auto;max-width:1200px;display:flex;flex-direction:column;gap:24px;}
@media (max-width:768px){.ssl-manager{padding:18px;}}
.ssl-manager__header{display:flex;flex-wrap:wrap;justify-content:space-between;gap:16px;padding-bottom:16px;border-bottom:1px solid #e2e8f0;}
.ssl-manager__header--tokens{align-items:flex-start;}
.ssl-manager__title h2{margin:0;color:#0f172a;font-size:1.75rem;font-weight:700;}
.ssl-manager__subtitle{color:#64748b;font-size:.95rem;margin-top:4px;}
.ssl-manager__header-actions{display:flex;gap:10px;align-items:center;}
.ssl-toolbar{display:grid;grid-template-columns:repeat(auto-fit,minmax(240px,1fr));gap:12px;}
.ssl-footer-tools{padding-top:16px;border-top:1px solid #e2e8f0;display:flex;flex-direction:column;gap:16px;}
.ssl-toolbar--bottom{width:100%;}
.ssl-toolbar__group,.ssl-toolbar__import{display:flex;gap:10px;align-items:center;justify-content:flex-start;background:#f8fafc;border:1px solid #e2e8f0;border-radius:12px;padding:12px;}
.ssl-toolbar__group--end{justify-content:flex-end;}
.ssl-toolbar__import{justify-content:space-between;flex-wrap:wrap;}
.ssl-toolbar--filters .ssl-toolbar__group{background:transparent;border:none;padding:0;max-width:320px;}
.ssl-toolbar--filters label{display:flex;flex-direction:column;gap:6px;width:100%;color:#475569;font-weight:600;font-size:.85rem;}
.ssl-toolbar--filters input[type=search]{border:1px solid #cbd5f5;border-radius:10px;padding:.4rem .6rem;background:#fff;color:#1f2937;font-size:.9rem;}
.ssl-toolbar__import input[type=file]{flex:1 1 180px;font-size:.9rem;color:#475569;}
.ssl-page-size{display:flex;align-items:center;gap:8px;background:#f8fafc;border:1px solid #cbd5f5;border-radius:10px;padding:6px 12px;font-size:.9rem;color:#1e293b;}
.ssl-page-size label{display:flex;align-items:center;gap:8px;margin:0;font-weight:600;color:#1e293b;}
.ssl-page-size select{border:none;background:transparent;font-size:.95rem;font-weight:600;color:#1e293b;min-width:80px;padding:0;}
.ssl-page-size select:focus{outline:none;}
.ssl-pagination{margin-top:16px;display:flex;justify-content:center;}
.ssl-pagination__list{display:flex;gap:6px;list-style:none;margin:0;padding:0;}
.ssl-pagination__item .page-numbers{display:inline-flex;align-items:center;justify-content:center;padding:.45rem .9rem;border-radius:10px;border:1px solid #cbd5f5;background:#fff;color:#1e293b;font-weight:600;min-width:42px;text-decoration:none;transition:background .15s ease,color .15s ease,box-shadow .15s ease;}
.ssl-pagination__item .page-numbers:hover{background:#eef2ff;color:#1e3a8a;}
.ssl-pagination__item .page-numbers.current{background:linear-gradient(135deg,#4c6ef5,#364fc7);color:#fff;border-color:transparent;box-shadow:0 10px 18px rgba(54,79,199,.28);}
.ssl-btn{display:inline-flex;align-items:center;justify-content:center;gap:6px;padding:.2rem .7rem;border-radius:10px;border:1px solid transparent;font-weight:600;font-size:.95rem;cursor:pointer;text-decoration:none;transition:transform .15s ease,box-shadow .15s ease,background .15s ease,color .15s ease;}
.ssl-btn:focus{outline:2px solid #c7d2fe;outline-offset:2px;}
.ssl-btn.is-active{box-shadow:0 0 0 3px rgba(76,110,245,.25);}
.ssl-btn-primary{background:linear-gradient(135deg,#4c6ef5,#364fc7);color:#fff;box-shadow:0 8px 16px rgba(76,110,245,.28);}
.ssl-btn-primary:hover{transform:translateY(-1px);box-shadow:0 10px 22px rgba(54,79,199,.32);}
.ssl-btn-surface{background:#fff;border-color:#cbd5f5;color:#1e3a8a;box-shadow:0 4px 12px rgba(15,23,42,.08);}
.ssl-btn-surface:hover{background:#f8fafc;}
.ssl-btn-outline{background:transparent;border-color:#cbd5f5;color:#1f2937;}
.ssl-btn-outline:hover{background:#f8fafc;}
.ssl-btn-ghost{background:transparent;border:none;color:#475569;padding:0 .6rem;}
.ssl-btn-danger{background:linear-gradient(135deg,#f87171,#ef4444);color:#fff;box-shadow:0 8px 16px rgba(239,68,68,.24);}
.ssl-table{width:100%;border-collapse:separate;border-spacing:0;background:#fff;border-radius:16px;overflow:hidden;box-shadow:0 14px 28px rgba(15,23,42,.05);}
.ssl-table thead th{background:#f1f5f9;color:#0f172a;padding:14px 12px;text-align:right;font-size:.95rem;font-weight:700;border-bottom:1px solid #e2e8f0;}
.ssl-table tbody td{padding:14px 12px;border-bottom:1px solid #e2e8f0;vertical-align:middle;color:#1e293b;font-size:.95rem;text-align:right;}
.ssl-table tbody tr:nth-child(even){background:#f8fafc;}
.ssl-table tbody tr:hover{background:#eef2ff;}
.ssl-table tbody tr:last-child td{border-bottom:none;}
.ssl-table tbody td img{max-width:60px;max-height:60px;margin:2px;border-radius:8px;box-shadow:0 4px 10px rgba(15,23,42,.12);}
.ssl-sort-link{color:inherit;text-decoration:none;display:inline-flex;align-items:center;gap:4px;font-weight:700;}
.ssl-sort-link:hover{color:#1e3a8a;}
.ssl-group-toggle{border:none;background:#e2e8f0;color:#1e3a8a;border-radius:999px;padding:.2rem .6rem;font-size:.8rem;font-weight:700;cursor:pointer;margin-left:6px;}
.ssl-group-toggle[aria-expanded="true"]{background:#1e3a8a;color:#fff;}
.ssl-group-meta{font-size:.75rem;color:#64748b;margin-top:4px;}
.ssl-table tr[data-ssl-group-child]{background:#f8fafc;}
.ssl-table tr[data-ssl-group-child] td:first-child{padding-right:36px;position:relative;}
.ssl-table tr[data-ssl-group-child] td:first-child:before{content:'↳';position:absolute;right:12px;top:50%;transform:translateY(-50%);color:#94a3b8;}
.ssl-row-details td:first-child{padding-right:16px;}
.ssl-row-details td:first-child:before{display:none;}
.ssl-row-details td{background:#f1f5f9;font-size:.85rem;color:#475569;}
.ssl-row-details__wrap{display:flex;flex-wrap:wrap;gap:16px;align-items:flex-start;}
.ssl-row-details__section{flex:1 1 240px;display:flex;flex-direction:column;gap:8px;}
.ssl-row-details__section h4{margin:0;font-size:.85rem;color:#0f172a;}
.ssl-row-details__images{display:flex;flex-wrap:wrap;gap:8px;}
.ssl-row-details__images a{display:inline-flex;}
.ssl-row-details__error{color:#b91c1c;font-weight:600;}
.ssl-manager--compact .ssl-table thead th,.ssl-manager--compact .ssl-table tbody td{padding:8px 10px;font-size:.85rem;}
.ssl-manager--compact .ssl-btn{padding:.14rem .45rem;font-size:.85rem;}
.ssl-manager--compact .ssl-toolbar__group,.ssl-manager--compact .ssl-toolbar__import{gap:6px;padding:8px;}
.ssl-manager--compact .ssl-card,.ssl-manager--compact .ssl-card__footer{gap:10px;}
.ssl-badge{display:inline-flex;align-items:center;justify-content:center;padding:.35rem .85rem;border-radius:999px;font-weight:700;min-width:72px;box-shadow:inset 0 -2px 0 rgba(255,255,255,.6);}
.ssl-green{background:#dcfce7;color:#0f766e;}
.ssl-yellow{background:#fef3c7;color:#b45309;}
.ssl-red{background:#fee2e2;color:#b91c1c;}
.ssl-form,.ssl-card{background:#fff;border:1px solid #e2e8f0;border-radius:14px;padding:20px;box-shadow:0 10px 24px rgba(15,23,42,.06);display:flex;flex-direction:column;gap:16px;}
.ssl-card__header{display:flex;justify-content:space-between;align-items:center;gap:12px;}
.ssl-card__header h3{margin:0;font-size:1.1rem;color:#0f172a;}
.ssl-card__body{display:grid;gap:14px;}
.ssl-card--form label.ssl-card__inline{flex-direction:row;align-items:center;gap:12px;}
.ssl-card--form label.ssl-card__inline span{flex:1;}
.ssl-token-row{display:flex;gap:12px;align-items:center;flex-wrap:wrap;}
.ssl-token-input{flex:1 1 320px;border:1px solid #d0d5dd;border-radius:10px;padding:.55rem .75rem;background:#f8fafc;font-family:monospace;font-size:1rem;color:#0f172a;}
.ssl-token-input:focus{outline:2px solid #c7d2fe;outline-offset:2px;}
.ssl-token-form{display:flex;gap:10px;flex-wrap:wrap;}
.ssl-token-form--stack{flex-direction:column;align-items:stretch;gap:16px;}
.ssl-token-manage{display:flex;flex-direction:column;gap:16px;}
.ssl-card--token .ssl-card__body label{width:100%;}
.ssl-card--links{border:none;box-shadow:none;padding:0;margin-top:16px;}
.ssl-card--links .ssl-card__footer{padding:0;}
.ssl-card__footer--links{justify-content:flex-start;}
.ssl-card__footer{display:flex;gap:10px;align-items:center;flex-wrap:wrap;justify-content:flex-start;}
.ssl-card--form label{display:flex;flex-direction:column;gap:6px;color:#475569;font-weight:600;font-size:.9rem;}
.ssl-card--form input[type=text],.ssl-card--form input[type=url],.ssl-card--form input[type=file],.ssl-card--form textarea,.ssl-card--form select{border:1px solid #d0d5dd;border-radius:10px;padding:.55rem .75rem;background:#f8fafc;color:#1f2937;font-size:.95rem;}
.ssl-card--form textarea{min-height:110px;resize:vertical;}
.ssl-card--form input[type=file]{padding:.45rem;}
.ssl-card--form input[type=checkbox]{margin-left:6px;transform:scale(1.1);}
.ssl-card--form .ssl-note{margin-top:4px;}
.ssl-note{font-size:.85rem;color:#64748b;}
.ssl-token-create{display:flex;flex-direction:column;gap:12px;}
.ssl-token-create__fields{display:flex;flex-wrap:wrap;gap:12px;align-items:flex-end;}
.ssl-token-create__fields label{flex:1 1 240px;margin:0;gap:4px;}
.ssl-token-create__fields label span{display:block;color:#475569;font-weight:600;font-size:.85rem;margin-bottom:2px;}
.ssl-token-create__fields input[type=text]{width:100%;padding:.5rem .75rem;border-radius:10px;border:1px solid #cbd5f5;background:#f8fafc;color:#1f2937;font-size:.95rem;}
.ssl-token-table{margin-top:8px;}
.ssl-token-table input[type=text]{width:100%;padding:.45rem .6rem;border:1px solid #cbd5f5;border-radius:8px;background:#f8fafc;color:#0f172a;font-size:.9rem;}
.ssl-token-table input[type=text][readonly]{cursor:text;}
.ssl-token-table__name{min-width:220px;}
.ssl-token-table__token{font-family:monospace;font-size:.9rem;}
.ssl-token-table__status{min-width:220px;}
 .ssl-token-table__actions{display:flex;gap:8px;justify-content:flex-end;flex-wrap:wrap;}
 .ssl-token-hidden-form{display:none;}
.ssl-token-status{display:flex;gap:10px;align-items:flex-start;}
.ssl-token-status__dot{width:12px;height:12px;border-radius:50%;box-shadow:0 0 0 4px rgba(148,163,184,.18);margin-top:6px;}
.ssl-token-status__dot--online{background:#22c55e;box-shadow:0 0 0 4px rgba(34,197,94,.18);}
.ssl-token-status__dot--offline{background:#ef4444;box-shadow:0 0 0 4px rgba(239,68,68,.18);}
.ssl-token-status__dot--unknown{background:#94a3b8;box-shadow:0 0 0 4px rgba(148,163,184,.2);}
.ssl-token-status__text{display:flex;flex-direction:column;gap:4px;}
.ssl-token-status__label{font-weight:700;color:#0f172a;}
.ssl-token-status__meta{font-size:.8rem;color:#64748b;}
.ssl-token-status__meta--error{color:#b91c1c;}
.ssl-token-table__notify,.ssl-token-table__emails{vertical-align:top;}
.ssl-token-toggle{display:flex;align-items:center;gap:8px;font-size:.85rem;color:#0f172a;font-weight:600;}
.ssl-token-toggle input[type=checkbox]{margin:0;}
.ssl-token-emails{display:flex;flex-direction:column;gap:8px;}
.ssl-token-email-list{display:flex;flex-wrap:wrap;gap:8px;min-height:32px;}
.ssl-token-email-chip{display:inline-flex;align-items:center;gap:6px;background:#e0f2fe;color:#0f172a;padding:.35rem .65rem;border-radius:999px;font-weight:600;font-size:.8rem;box-shadow:0 6px 14px rgba(14,116,144,.18);}
.ssl-token-email-chip__text{direction:ltr;}
.ssl-token-email-chip__remove{background:transparent;border:none;color:#1d4ed8;cursor:pointer;font-size:1rem;line-height:1;padding:0;}
.ssl-token-email-chip__remove:hover{color:#1e3a8a;}
.ssl-token-email-chip--empty{background:#f1f5f9;color:#64748b;box-shadow:none;font-weight:500;}
.ssl-token-email-add{display:flex;flex-wrap:wrap;gap:8px;align-items:center;}
.ssl-token-email-add input{flex:1 1 220px;border:1px solid #cbd5f5;border-radius:10px;padding:.45rem .6rem;background:#fff;color:#0f172a;font-size:.85rem;direction:ltr;}
.ssl-token-email-add button{padding:.45rem 1.1rem;}
.ssl-token-email-error{font-size:.75rem;color:#b91c1c;min-height:1.1em;}
.ssl-token-email-input--error{border-color:#f87171;box-shadow:0 0 0 2px rgba(248,113,113,.25);}
.ssl-log-table__time{white-space:nowrap;font-variant-numeric:tabular-nums;}
.ssl-log-table__level{min-width:110px;}
.ssl-log-level{display:inline-flex;align-items:center;justify-content:center;padding:.3rem .75rem;border-radius:999px;font-weight:700;font-size:.8rem;letter-spacing:.03em;text-transform:uppercase;box-shadow:inset 0 -2px 0 rgba(255,255,255,.45);}
.ssl-log-level--info{background:#e0f2fe;color:#0369a1;}
.ssl-log-level--warning{background:#fef3c7;color:#92400e;}
.ssl-log-level--error{background:#fee2e2;color:#b91c1c;}
.ssl-log-table__message{max-width:320px;white-space:normal;}
.ssl-log-table__context{min-width:260px;white-space:normal;}
.ssl-log-context{margin:0;padding:0;list-style:none;display:flex;flex-direction:column;gap:4px;}
.ssl-log-context__key{font-weight:700;color:#0f172a;margin-left:6px;}
.ssl-log-context__value{direction:ltr;font-family:"Fira Code","Source Code Pro",monospace;font-size:.82rem;color:#1e293b;word-break:break-all;}
.ssl-log-context__empty{color:#94a3b8;font-style:italic;}
.ssl-token-note{margin-top:12px;}
.ssl-actions{display:flex;gap:8px;flex-wrap:wrap;justify-content:flex-end;}
.ssl-table__edit-row td{background:#f8fafc;}
.ssl-empty{text-align:center;padding:24px;font-size:1rem;color:#64748b;}
@media (max-width:640px){
 .ssl-toolbar{grid-template-columns:1fr;}
 .ssl-toolbar__group,.ssl-toolbar__import{flex-direction:column;align-items:stretch;}
 .ssl-toolbar__group--end{justify-content:flex-start;}
 .ssl-manager__header-actions{width:100%;justify-content:stretch;}
 .ssl-manager__header-actions .ssl-btn{flex:1;}
 .ssl-actions{justify-content:center;}
 .ssl-token-create__fields{flex-direction:column;align-items:stretch;}
 .ssl-token-table__actions{justify-content:center;}
 .ssl-token-status{flex-direction:column;align-items:flex-start;}
 .ssl-token-email-add{flex-direction:column;align-items:stretch;}
 .ssl-token-email-add input,.ssl-token-email-add button{width:100%;flex:1 1 auto;}
 .ssl-token-email-list{justify-content:flex-start;}
}
.ssl-err{color:#b00020;font-size:.85rem;}
CSS;
        wp_register_style('ssl-expiry-manager', false);
        wp_enqueue_style('ssl-expiry-manager');
        wp_add_inline_style('ssl-expiry-manager', $css);
        $js = <<<'JS'
function sslEmailFindWrapper(el){
  return el ? el.closest('[data-email-list]') : null;
}
function sslEmailShowError(wrapper,message){
  if(!wrapper) return;
  var error = wrapper.querySelector('[data-email-error]');
  if(error){
    error.textContent = message || '';
  }
}
function sslEmailEnsure(wrapper){
  if(!wrapper) return;
  var list = wrapper.querySelector('[data-email-chips]');
  if(!list) return;
  var emptyNodes = list.querySelectorAll('[data-email-empty]');
  var hasChip = list.querySelector('[data-email-item]');
  if(hasChip){
    emptyNodes.forEach(function(node){ node.remove(); });
  } else if(!emptyNodes.length){
    var empty = document.createElement('span');
    empty.className = 'ssl-token-email-chip ssl-token-email-chip--empty';
    empty.setAttribute('data-email-empty','');
    empty.textContent = 'אין נמענים';
    list.appendChild(empty);
  }
}
function sslEmailHandleAdd(wrapper){
  if(!wrapper) return;
  var input = wrapper.querySelector('[data-email-input]');
  if(!input) return;
  var raw = input.value.trim();
  sslEmailShowError(wrapper,'');
  input.classList.remove('ssl-token-email-input--error');
  if(!raw){
    sslEmailShowError(wrapper,'הקלד כתובת דוא"ל');
    input.classList.add('ssl-token-email-input--error');
    return;
  }
  var email = raw.toLowerCase();
  var pattern = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if(!pattern.test(email)){
    sslEmailShowError(wrapper,'כתובת לא תקינה');
    input.classList.add('ssl-token-email-input--error');
    return;
  }
  var exists = Array.prototype.slice.call(wrapper.querySelectorAll('input[type="hidden"][name="token_emails[]"]')).some(function(hidden){
    return hidden.value.toLowerCase() === email;
  });
  if(exists){
    sslEmailShowError(wrapper,'כתובת כבר קיימת');
    input.value = '';
    return;
  }
  var list = wrapper.querySelector('[data-email-chips]');
  if(!list) return;
  var chip = document.createElement('span');
  chip.className = 'ssl-token-email-chip';
  chip.setAttribute('data-email-item','');
  var hidden = document.createElement('input');
  hidden.type = 'hidden';
  hidden.name = 'token_emails[]';
  hidden.value = email;
  var formId = wrapper.getAttribute('data-email-form');
  if(formId){ hidden.setAttribute('form', formId); }
  var text = document.createElement('span');
  text.className = 'ssl-token-email-chip__text';
  text.textContent = raw;
  var remove = document.createElement('button');
  remove.type = 'button';
  remove.className = 'ssl-token-email-chip__remove';
  remove.setAttribute('data-email-remove','');
  remove.setAttribute('aria-label','הסר כתובת');
  remove.textContent = '×';
  chip.appendChild(hidden);
  chip.appendChild(text);
  chip.appendChild(remove);
  list.appendChild(chip);
  input.value = '';
  sslEmailEnsure(wrapper);
}
document.addEventListener('click',function(e){
  var toggle = e.target.closest('[data-ssl-toggle]');
  if(toggle){
    var action = toggle.getAttribute('data-ssl-toggle');
    if(action==='create'){
      var form = document.querySelector('[data-ssl-create]');
      if(form){
        e.preventDefault();
        if(form.hasAttribute('hidden')){form.removeAttribute('hidden');}
        else{form.setAttribute('hidden','');}
        document.querySelectorAll('[data-ssl-toggle="create"]').forEach(function(btn){
          if(form.hasAttribute('hidden')) btn.classList.remove('is-active');
          else btn.classList.add('is-active');
        });
      }
    }
  }
  var edit = e.target.closest('[data-ssl-edit]');
  if(edit){
    e.preventDefault();
    var id = edit.getAttribute('data-ssl-edit');
    var row = document.querySelector('[data-ssl-form="'+id+'"]');
    if(row){
      if(row.hasAttribute('hidden')){row.removeAttribute('hidden');}
      else{row.setAttribute('hidden','');}
      document.querySelectorAll('[data-ssl-edit="'+id+'"]').forEach(function(btn){
        if(row.hasAttribute('hidden')) btn.classList.remove('is-active');
        else btn.classList.add('is-active');
      });
    }
  }
  var removeBtn = e.target.closest('[data-email-remove]');
  if(removeBtn){
    var wrapper = sslEmailFindWrapper(removeBtn);
    if(wrapper){
      e.preventDefault();
      var chip = removeBtn.closest('[data-email-item]');
      if(chip){ chip.remove(); }
      sslEmailShowError(wrapper,'');
      sslEmailEnsure(wrapper);
    }
  }
  if(e.target.matches('[data-email-add]')){
    var addWrapper = sslEmailFindWrapper(e.target);
    if(addWrapper){
      e.preventDefault();
      sslEmailHandleAdd(addWrapper);
    }
  }
  var groupToggle = e.target.closest('[data-ssl-group-toggle]');
  if(groupToggle){
    e.preventDefault();
    var groupKey = groupToggle.getAttribute('data-ssl-group-toggle');
    var expanded = groupToggle.getAttribute('aria-expanded') === 'true';
    var nextState = !expanded;
    groupToggle.setAttribute('aria-expanded', nextState ? 'true' : 'false');
    groupToggle.textContent = nextState ? '−' : '+';
    document.querySelectorAll('[data-ssl-group-child="'+groupKey+'"]').forEach(function(row){
      if(nextState){
        row.removeAttribute('hidden');
      } else {
        row.setAttribute('hidden','');
      }
    });
  }
});
document.addEventListener('keydown',function(e){
  if(e.key==='Enter' && e.target.matches('[data-email-input]')){
    var wrapper = sslEmailFindWrapper(e.target);
    if(wrapper){
      e.preventDefault();
      sslEmailHandleAdd(wrapper);
    }
  }
});
window.addEventListener('DOMContentLoaded',function(){
  var createForm=document.querySelector('[data-ssl-create]');
  if(createForm && !createForm.hasAttribute('hidden')){
    document.querySelectorAll('[data-ssl-toggle="create"]').forEach(function(btn){btn.classList.add('is-active');});
  }
  document.querySelectorAll('[data-ssl-form]').forEach(function(row){
    if(!row.hasAttribute('hidden')){
      var id=row.getAttribute('data-ssl-form');
      document.querySelectorAll('[data-ssl-edit="'+id+'"]').forEach(function(btn){btn.classList.add('is-active');});
    }
  });
  document.querySelectorAll('[data-email-list]').forEach(function(wrapper){
    sslEmailEnsure(wrapper);
  });
  document.querySelectorAll('[data-ssl-page-size]').forEach(function(select){
    select.addEventListener('change',function(){
      var form = select.closest('form');
      if(form){
        var pageInput = form.querySelector('[data-ssl-page-input]');
        if(pageInput){
          pageInput.value = '1';
        }
        form.submit();
      }
    });
  });
  document.querySelectorAll('[data-ssl-filter-form]').forEach(function(form){
    var debounceTimer = null;
    var submitForm = function(){
      if(debounceTimer){
        clearTimeout(debounceTimer);
        debounceTimer = null;
      }
      var pageInput = form.querySelector('input[name="ssl_page"]');
      if(pageInput){
        pageInput.value = '1';
      }
      if(typeof form.requestSubmit === 'function'){
        form.requestSubmit();
      } else {
        form.submit();
      }
    };
    var scheduleSubmit = function(){
      if(debounceTimer){
        clearTimeout(debounceTimer);
      }
      debounceTimer = setTimeout(submitForm, 400);
    };
    var searchInput = form.querySelector('[data-ssl-filter-search]');
    if(searchInput){
      searchInput.addEventListener('input', scheduleSubmit);
    }
    form.querySelectorAll('[data-ssl-filter-select]').forEach(function(select){
      select.addEventListener('change', submitForm);
    });
  });
  document.querySelectorAll('[data-ssl-group-parent]').forEach(function(row){
    var btn = row.querySelector('[data-ssl-group-toggle]');
    if(btn){
      btn.setAttribute('aria-expanded','false');
      btn.textContent = '+';
    }
  });
});
JS;
        wp_register_script('ssl-expiry-manager-js','',[],false,true);
        wp_enqueue_script('ssl-expiry-manager-js');
        wp_add_inline_script('ssl-expiry-manager-js',$js);
    }

    private function nonce_field(){ return wp_nonce_field(self::NONCE, self::NONCE, true, false); }
    private function check_nonce(){ if(!isset($_POST[self::NONCE])||!wp_verify_nonce($_POST[self::NONCE], self::NONCE)) wp_die('Invalid nonce'); }
    private function sanitize_url($url){ $url=trim($url); if($url && !preg_match('#^https?://#i',$url)) $url='https://'.$url; return esc_url_raw($url); }
    private function days_left($ts){ if(!$ts) return null; $now=current_time('timestamp'); return (int)floor(($ts-$now)/DAY_IN_SECONDS); }
    private function badge_class($d){ if($d===null) return ''; if($d>90) return 'ssl-green'; if($d>30) return 'ssl-yellow'; return 'ssl-red'; }
    private function fmt_date($ts){ return $ts ? date_i18n('d-m-Y', $ts) : ''; }
    private function parse_user_date($value){
        $value = trim((string)$value);
        if($value === ''){
            return null;
        }
        $formats = ['d-m-Y','Y-m-d'];
        foreach($formats as $format){
            $dt = \DateTime::createFromFormat($format, $value);
            if($dt instanceof \DateTime){
                $errors = \DateTime::getLastErrors();
                if(empty($errors['warning_count']) && empty($errors['error_count'])){
                    $dt->setTime(0, 0, 0);
                    return $dt->getTimestamp();
                }
            }
        }
        $ts = strtotime($value);
        if($ts){
            return $ts;
        }
        return null;
    }
    private function url_btn($u){ if(!$u) return ''; $u=esc_url($u); return "<a class='ssl-btn ssl-btn-outline' target='_blank' rel='noopener' href='{$u}'>פתיחת אתר</a>"; }
    private function get_activity_log(){
        $log = get_option(self::OPTION_LOG, []);
        if(!is_array($log)){
            $log = [];
        }
        return $log;
    }
    private function sanitize_log_context($context){
        $clean = [];
        foreach((array)$context as $key => $value){
            $clean_key = is_string($key) ? sanitize_key($key) : $key;
            if(is_scalar($value) || $value === null){
                $clean[$clean_key] = is_string($value) ? wp_strip_all_tags((string)$value) : $value;
            } elseif(is_array($value)){
                $clean[$clean_key] = $this->sanitize_log_context($value);
            }
        }
        return $clean;
    }

    private function format_log_context_display($context){
        if(empty($context) || !is_array($context)){
            return '<span class="ssl-log-context__empty">—</span>';
        }
        $items = [];
        foreach($context as $key => $value){
            $label = is_string($key) ? sanitize_key($key) : $key;
            if(is_array($value)){
                $encoded = wp_json_encode($value, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
                $value = $encoded !== false ? $encoded : '';
            }
            if(is_bool($value)){
                $value = $value ? 'true' : 'false';
            } elseif($value === null){
                $value = 'null';
            }
            if(!is_scalar($value)){
                $value = '';
            }
            $items[] = '<li><span class="ssl-log-context__key">'.esc_html((string)$label).'</span><span class="ssl-log-context__value">'.esc_html((string)$value).'</span></li>';
        }
        if(empty($items)){
            return '<span class="ssl-log-context__empty">—</span>';
        }
        return '<ul class="ssl-log-context">'.implode('', $items).'</ul>';
    }
    private function get_current_actor_context(){
        $context = ['actor' => 'מערכת'];
        if(function_exists('is_user_logged_in') && is_user_logged_in()){
            $user = wp_get_current_user();
            if($user && $user->ID){
                $label = $user->display_name ?: $user->user_login;
                if(!$label){
                    $label = 'משתמש #'.$user->ID;
                }
                $context['actor'] = $label;
                $context['actor_id'] = (int)$user->ID;
                if(!empty($user->user_email)){
                    $context['actor_email'] = sanitize_email($user->user_email);
                }
                return $context;
            }
        }
        if(!empty($_SERVER['REMOTE_ADDR'])){
            $ip = sanitize_text_field(wp_unslash($_SERVER['REMOTE_ADDR']));
            $context['actor'] = 'אורח '.$ip;
            $context['actor_ip'] = $ip;
        }
        return $context;
    }
    private function log_activity($message, array $context = [], $level = 'info'){
        $level = in_array($level, ['info','warning','error'], true) ? $level : 'info';
        $entry = [
            'time'    => time(),
            'level'   => $level,
            'message' => wp_strip_all_tags((string)$message),
            'context' => $this->sanitize_log_context($context),
        ];
        $log = $this->get_activity_log();
        $log[] = $entry;
        if(count($log) > 200){
            $log = array_slice($log, -200);
        }
        update_option(self::OPTION_LOG, $log, false);
    }
    private function normalize_queue_items($items){
        $normalized = [];
        $changed = false;
        foreach((array)$items as $item){
            if(!is_array($item)){
                $changed = true;
                continue;
            }
            $id  = isset($item['id']) ? (int)$item['id'] : 0;
            $url = isset($item['site_url']) ? (string)$item['site_url'] : '';
            if($id <= 0 || $url === ''){
                $changed = true;
                continue;
            }
            $request_id = isset($item['request_id']) ? preg_replace('/[^a-zA-Z0-9_-]/', '', (string)$item['request_id']) : '';
            if($request_id === ''){
                $request_id = 'job'.wp_generate_password(10, false, false);
                $changed = true;
            }
            $status = isset($item['status']) && in_array($item['status'], ['queued','claimed'], true) ? $item['status'] : 'queued';
            if(!isset($item['status']) || $item['status'] !== $status){
                $changed = true;
            }
            $normalized[] = [
                'id'          => $id,
                'site_url'    => esc_url_raw($url),
                'client_name' => isset($item['client_name']) ? wp_strip_all_tags((string)$item['client_name']) : '',
                'context'     => isset($item['context']) && $item['context'] !== '' ? sanitize_key($item['context']) : 'manual',
                'agent_only'  => !empty($item['agent_only']) ? 1 : 0,
                'enqueued_at' => isset($item['enqueued_at']) ? (int)$item['enqueued_at'] : time(),
                'request_id'  => $request_id,
                'status'      => $status,
                'claimed_at'  => isset($item['claimed_at']) ? (int)$item['claimed_at'] : 0,
                'attempts'    => isset($item['attempts']) ? (int)$item['attempts'] : 0,
            ];
        }
        return [$normalized, $changed];
    }
    private function get_task_queue(){
        $queue = get_option(self::OPTION_QUEUE, []);
        if(!is_array($queue)){
            $queue = [];
        }
        [$normalized, $changed] = $this->normalize_queue_items($queue);
        if($changed){
            update_option(self::OPTION_QUEUE, $normalized, false);
        }
        return $normalized;
    }
    private function save_task_queue($queue){
        [$normalized, ] = $this->normalize_queue_items($queue);
        update_option(self::OPTION_QUEUE, $normalized, false);
    }
    private function release_stale_claims(&$queue){
        $changed = false;
        $now = time();
        foreach($queue as &$item){
            if($item['status'] === 'claimed' && (!empty($item['claimed_at']))){
                if(($now - (int)$item['claimed_at']) > self::QUEUE_CLAIM_TTL){
                    $item['status'] = 'queued';
                    $item['claimed_at'] = 0;
                    $changed = true;
                }
            }
        }
        unset($item);
        return $changed;
    }
    private function enqueue_task($post_id, $context = 'manual'){
        $post_id = (int)$post_id;
        if($post_id <= 0){
            return false;
        }
        $url = (string)get_post_meta($post_id, 'site_url', true);
        if(!$url){
            return false;
        }
        $queue = $this->get_task_queue();
        foreach($queue as $index => $item){
            if((int)$item['id'] === $post_id){
                unset($queue[$index]);
            }
        }
        $queue[] = [
            'id'          => $post_id,
            'site_url'    => esc_url_raw($url),
            'client_name' => (string)get_post_meta($post_id, 'client_name', true),
            'context'     => $context,
            'agent_only'  => (int)get_post_meta($post_id, 'agent_only', true) ? 1 : 0,
            'enqueued_at' => time(),
            'request_id'  => 'job'.wp_generate_password(10, false, false),
            'status'      => 'queued',
            'claimed_at'  => 0,
            'attempts'    => 0,
        ];
        $queue = array_values($queue);
        $this->save_task_queue($queue);
        update_post_meta($post_id,'expiry_ts_checked_at', time());
        $this->sync_table_record($post_id, get_post_status($post_id));
        $post = get_post($post_id);
        $client_name = (string)get_post_meta($post_id,'client_name',true);
        $this->log_activity('המשימה נוספה לתור', array_merge([
            'id' => $post_id,
            'context' => $context,
            'site_url' => $url,
            'client_name' => $client_name,
            'check_name' => $post ? $post->post_title : $client_name,
        ], $this->get_current_actor_context()));
        return true;
    }
    private function claim_queue_tasks($limit, $agent_filter = null, $token_label = ''){
        $limit = min(100, max(1, (int)$limit));
        $queue = $this->get_task_queue();
        $changed = $this->release_stale_claims($queue);
        $claimed = [];
        $now = time();
        foreach($queue as &$item){
            if($item['status'] !== 'queued'){
                continue;
            }
            if($agent_filter === true && empty($item['agent_only'])){
                continue;
            }
            if($agent_filter === false && !empty($item['agent_only'])){
                continue;
            }
            $item['status'] = 'claimed';
            $item['claimed_at'] = $now;
            $item['attempts'] = isset($item['attempts']) ? (int)$item['attempts'] + 1 : 1;
            $claimed[] = $item;
            $changed = true;
            if(count($claimed) >= $limit){
                break;
            }
        }
        unset($item);
        if($changed){
            $this->save_task_queue($queue);
        }
        if(!empty($claimed)){
            $jobs = [];
            foreach($claimed as $job){
                $jobs[] = [
                    'id' => (int)$job['id'],
                    'client_name' => $job['client_name'],
                    'site_url' => $job['site_url'],
                    'context' => $job['context'],
                ];
            }
            $this->log_activity('משימות נמסרו לסוכן', array_merge([
                'count' => count($claimed),
                'token' => $token_label,
                'jobs' => $jobs,
            ], $this->get_current_actor_context()));
        }
        $callback = rest_url('ssl-agent/v1/report');
        foreach($claimed as &$job){
            $job['callback'] = $callback;
        }
        unset($job);
        return $claimed;
    }
    private function peek_queue_tasks($limit, $agent_filter = null){
        $limit = min(100, max(1, (int)$limit));
        $queue = $this->get_task_queue();
        $changed = $this->release_stale_claims($queue);
        if($changed){
            $this->save_task_queue($queue);
        }
        $tasks = [];
        foreach($queue as $item){
            if($item['status'] !== 'queued'){
                continue;
            }
            if($agent_filter === true && empty($item['agent_only'])){
                continue;
            }
            if($agent_filter === false && !empty($item['agent_only'])){
                continue;
            }
            $tasks[] = $item + ['callback' => rest_url('ssl-agent/v1/report')];
            if(count($tasks) >= $limit){
                break;
            }
        }
        return $tasks;
    }
    private function complete_queue_task($post_id, $request_id, $success = true, $message = '', array $extra_context = []){
        $post_id = (int)$post_id;
        $request_id = (string)$request_id;
        $queue = $this->get_task_queue();
        $removed = false;
        $job_context = null;
        foreach($queue as $index => $item){
            if((int)$item['id'] === $post_id){
                if($request_id && $item['request_id'] !== $request_id){
                    continue;
                }
                $job_context = $item;
                unset($queue[$index]);
                $removed = true;
            }
        }
        if($removed){
            $this->save_task_queue(array_values($queue));
        }
        $post = get_post($post_id);
        $client_name = is_array($job_context) && isset($job_context['client_name']) ? $job_context['client_name'] : ($post ? get_post_meta($post_id,'client_name',true) : '');
        $site_url = is_array($job_context) && isset($job_context['site_url']) ? $job_context['site_url'] : ($post ? get_post_meta($post_id,'site_url',true) : '');
        $attempts = is_array($job_context) && isset($job_context['attempts']) ? (int)$job_context['attempts'] : 0;
        $context_label = is_array($job_context) && isset($job_context['context']) ? $job_context['context'] : '';
        $agent_only_flag = is_array($job_context) && !empty($job_context['agent_only']);
        $log_context = array_merge([
            'id' => $post_id,
            'request_id' => $request_id,
            'site_url' => $site_url,
            'client_name' => $client_name,
            'check_name' => $post ? $post->post_title : $client_name,
            'queue_context' => $context_label,
            'status' => $success ? 'success' : 'failure',
            'message' => $message,
            'attempts' => $attempts,
            'agent_only' => $agent_only_flag,
            'checked_at' => date_i18n('Y-m-d H:i:s'),
        ], $extra_context, $this->get_current_actor_context());
        if(!empty($log_context['expiry_ts'])){
            $log_context['expiry_ts'] = (int)$log_context['expiry_ts'];
            if($log_context['expiry_ts'] > 0){
                $log_context['expiry_date'] = date_i18n('Y-m-d', $log_context['expiry_ts']);
            }
        }
        if($removed){
            $this->log_activity($success ? 'משימת בדיקה הסתיימה' : 'משימת בדיקה נכשלה', $log_context, $success ? 'info' : 'error');
        } else {
            $this->log_activity('משימה שלא נמצאה בתור', $log_context, 'warning');
        }
    }
    public function ensure_token_store(){
        $tokens = get_option(self::OPTION_TOKEN, null);
        if($tokens === null){
            add_option(self::OPTION_TOKEN, []);
            return;
        }
        if(!is_array($tokens)){
            if($tokens){
                $converted = [[
                    'id'      => $this->generate_token_id(),
                    'name'    => 'Token ראשי',
                    'token'   => (string)$tokens,
                    'created' => time(),
                    'updated' => time(),
                ]];
                update_option(self::OPTION_TOKEN, $converted);
            } else {
                update_option(self::OPTION_TOKEN, []);
            }
        } else {
            $normalized = $this->normalize_tokens($tokens);
            if($normalized !== $tokens){
                update_option(self::OPTION_TOKEN, $normalized);
            }
        }
    }

    public function ensure_queue_store(){
        $queue = get_option(self::OPTION_QUEUE, null);
        if($queue === null){
            add_option(self::OPTION_QUEUE, [], false);
            return;
        }
        if(!is_array($queue)){
            update_option(self::OPTION_QUEUE, [], false);
        }
    }

    public function ensure_log_store(){
        $log = get_option(self::OPTION_LOG, null);
        if($log === null){
            add_option(self::OPTION_LOG, [], false);
            return;
        }
        if(!is_array($log)){
            update_option(self::OPTION_LOG, [], false);
        }
    }
    private function normalize_tokens($tokens){
        $normalized = [];
        foreach((array)$tokens as $token){
            if(!is_array($token)) continue;
            $token['id'] = isset($token['id']) && $token['id'] ? sanitize_key($token['id']) : $this->generate_token_id();
            $token['name'] = isset($token['name']) && $token['name'] !== '' ? sanitize_text_field($token['name']) : 'ללא שם';
            $token['token'] = isset($token['token']) && $token['token'] ? (string)$token['token'] : $this->generate_token_value();
            $token['created'] = isset($token['created']) ? (int)$token['created'] : time();
            $token['updated'] = isset($token['updated']) ? (int)$token['updated'] : time();
            $status = isset($token['last_status']) ? strtolower((string)$token['last_status']) : 'unknown';
            if(!in_array($status, ['online','offline','unknown'], true)){
                $status = 'unknown';
            }
            $token['last_status'] = $status;
            $token['last_seen'] = isset($token['last_seen']) ? (int)$token['last_seen'] : 0;
            $token['last_error'] = isset($token['last_error']) ? sanitize_text_field($token['last_error']) : '';
            $token['notify_down'] = !empty($token['notify_down']) ? 1 : 0;
            $emails = [];
            if(isset($token['emails'])){
                foreach((array)$token['emails'] as $email){
                    $email = sanitize_email($email);
                    if($email){
                        $emails[$email] = $email;
                    }
                }
            }
            $token['emails'] = array_values($emails);
            $token['notified_down_at'] = isset($token['notified_down_at']) ? (int)$token['notified_down_at'] : 0;
            $normalized[] = $token;
        }
        return $normalized;
    }
    private function get_tokens(){
        $tokens = get_option(self::OPTION_TOKEN, []);
        if(!is_array($tokens)){
            $this->ensure_token_store();
            $tokens = get_option(self::OPTION_TOKEN, []);
        }
        return $this->normalize_tokens($tokens);
    }
    private function save_tokens($tokens){
        update_option(self::OPTION_TOKEN, $this->normalize_tokens($tokens));
    }
    private function ensure_default_token(){
        $tokens = $this->get_tokens();
        if(!empty($tokens)){
            return $tokens;
        }
        $default = [[
            'id'      => $this->generate_token_id(),
            'name'    => 'Token ראשי',
            'token'   => $this->generate_token_value(),
            'created' => time(),
            'updated' => time(),
            'last_status' => 'unknown',
            'last_seen'   => 0,
            'last_error'  => '',
            'notify_down' => 0,
            'emails'      => [],
            'notified_down_at' => 0,
        ]];
        $this->save_tokens($default);
        return $default;
    }
    private function generate_token_value(){
        return wp_generate_password(40, false, false);
    }
    private function generate_token_id(){
        return 'tok_'.wp_generate_password(8, false, false);
    }
    private function get_primary_token(){
        $tokens = $this->ensure_default_token();
        return $tokens[0] ?? null;
    }
    private function get_page_url($slug, $fallback){
        $page = get_page_by_path($slug);
        if($page){
            $url = get_permalink($page);
            if($url){
                return $url;
            }
        }
        return $fallback;
    }

    private function resolve_main_page_url(){
        foreach(['ssl-cert-table','ssl-manager','ssl-table'] as $slug){
            $candidate = $this->get_page_url($slug, '');
            if($candidate){
                return $candidate;
            }
        }
        return self::PAGE_MAIN_FALLBACK;
    }

    private function resolve_token_page_url(){
        $page = $this->get_page_url('ssl-token-page', '');
        if($page){
            return $page;
        }
        $legacy = $this->get_page_url('ssl-token', '');
        if($legacy){
            return $legacy;
        }
        return self::PAGE_TOKEN_FALLBACK;
    }

    private function resolve_trash_page_url(){
        return $this->get_page_url('ssl-trash', self::PAGE_TRASH_FALLBACK);
    }

    private function resolve_logs_page_url(){
        $page = $this->get_page_url('ssl-logs', '');
        if($page){
            return $page;
        }
        return self::PAGE_LOG_FALLBACK;
    }

    private function get_primary_token_value(){
        $token = $this->get_primary_token();
        if($token && !empty($token['token'])){
            return (string)$token['token'];
        }
        return '';
    }

    private function update_token_fields($token_id, array $changes){
        $tokens = $this->ensure_default_token();
        $updated = null;
        foreach($tokens as &$token){
            if($token['id'] !== $token_id){
                continue;
            }
            foreach($changes as $key => $value){
                $token[$key] = $value;
            }
            $updated = $token;
            break;
        }
        unset($token);
        if($updated !== null){
            $this->save_tokens($tokens);
        }
        return $updated;
    }

    private function mark_token_online($token_id){
        return $this->update_token_fields($token_id, [
            'last_seen' => time(),
            'last_status' => 'online',
            'last_error' => '',
            'notified_down_at' => 0,
        ]);
    }

    private function mark_token_offline($token_id, $message){
        return $this->update_token_fields($token_id, [
            'last_status' => 'offline',
            'last_error' => $message,
        ]);
    }

    private function maybe_notify_token_down($token, $message){
        if(empty($token['notify_down'])){
            return;
        }
        $recipients = array_filter(array_map('sanitize_email', (array)($token['emails'] ?? [])));
        if(empty($recipients)){
            return;
        }
        $already = isset($token['notified_down_at']) ? (int)$token['notified_down_at'] : 0;
        if($already && (time() - $already) < HOUR_IN_SECONDS){
            return;
        }
        if(!function_exists('wp_mail')){
            return;
        }
        $site = wp_specialchars_decode(get_bloginfo('name'), ENT_QUOTES);
        $subject = sprintf('התראת חיבור סוכן SSL - %s', $token['name']);
        $body = sprintf("שלום,\n\nהחיבור לסוכן ה-SSL עבור הטוקן \"%s\" נפל.\nהודעה אחרונה: %s\nאתר: %s\nזמן: %s\n\nהטוקן יסומן כמנותק עד שיתקבל חיבור מחודש.",
            $token['name'],
            $message ? $message : 'לא התקבלה שגיאה מפורטת',
            home_url('/'),
            date_i18n('d.m.Y H:i')
        );
        wp_mail($recipients, $subject.' - '.$site, $body);
        $this->update_token_fields($token['id'], ['notified_down_at' => time()]);
    }

    private function collect_token_email_choices(){
        $choices = [];
        $admin_email = sanitize_email(get_option('admin_email'));
        if($admin_email){
            $choices[$admin_email] = $admin_email.' (מנהל)';
        }
        $users = get_users(['fields' => ['ID','display_name','user_email']]);
        foreach($users as $user){
            $email = sanitize_email($user->user_email);
            if(!$email){
                continue;
            }
            $label = $email;
            if(!empty($user->display_name) && stripos($user->display_name, $email) === false){
                $label = $user->display_name.' <'.$email.'>';
            }
            $choices[$email] = $label;
        }
        return $choices;
    }

    private function parse_token_emails($selected, $extra){
        $emails = [];
        foreach((array)$selected as $email){
            $email = sanitize_email($email);
            if($email){
                $emails[$email] = $email;
            }
        }
        if($extra){
            $parts = preg_split('/[\s,;]+/', (string)$extra);
            foreach($parts as $email){
                $email = sanitize_email($email);
                if($email){
                    $emails[$email] = $email;
                }
            }
        }
        return array_values($emails);
    }

    private function get_remote_client_settings(){
        $saved = get_option(self::OPTION_REMOTE, []);
        if(!is_array($saved)){
            $saved = [];
        }
        $defaults = [
            'enabled' => 0,
            'local_fallback' => 1,
        ];
        $settings = wp_parse_args($saved, $defaults);
        $settings = [
            'enabled' => (int)!empty($settings['enabled']),
            'local_fallback' => (int)!empty($settings['local_fallback']),
        ];
        return $settings;
    }

    private function remote_client_is_ready($settings = null){
        if($settings === null){
            $settings = $this->get_remote_client_settings();
        }
        if(empty($settings['enabled'])){
            return false;
        }
        $primary = $this->get_primary_token();
        if(!$primary || empty($primary['token'])){
            return false;
        }
        return true;
    }

    private function dispatch_remote_check($post_id, $url, $context = 'manual', $settings = null){
        if($settings === null){
            $settings = $this->get_remote_client_settings();
        }
        if(!$this->remote_client_is_ready($settings)){
            return false;
        }
        $success = $this->enqueue_task($post_id, $context);
        if($success){
            $primary = $this->get_primary_token();
            if($primary){
                $this->mark_token_online($primary['id']);
            }
        }
        return $success;
    }

    public function shortcode_table($atts = []) {
        $default_trash = $this->resolve_trash_page_url();
        $default_token = $this->resolve_token_page_url();
        $default_logs  = $this->resolve_logs_page_url();
        $a = shortcode_atts([
            'trash_url' => $default_trash,
            'token_url' => $default_token,
            'logs_url'  => $default_logs,
        ], $atts);
        $per_page_choices = [25, 100, 500];
        $requested_per_page = isset($_GET['ssl_per_page']) ? intval($_GET['ssl_per_page']) : 25;
        if(!in_array($requested_per_page, $per_page_choices, true)){
            $requested_per_page = 25;
        }
        $current_page = isset($_GET['ssl_page']) ? max(1, intval($_GET['ssl_page'])) : 1;
        $preserved_query = [];
        if(!empty($_GET)){
            foreach($_GET as $key => $value){
                if(is_array($value)){
                    continue;
                }
                $preserved_query[$key] = sanitize_text_field(wp_unslash($value));
            }
        }
        $sort = isset($preserved_query['ssl_sort']) ? sanitize_key($preserved_query['ssl_sort']) : 'common_name';
        $order = isset($preserved_query['ssl_order']) && strtolower($preserved_query['ssl_order']) === 'desc' ? 'DESC' : 'ASC';
        $search = $preserved_query['ssl_search'] ?? '';
        if(isset($preserved_query['ssl_source'])){
            $source_filter = $this->normalize_source_value($preserved_query['ssl_source'], '');
        } else {
            $source_filter = '';
        }
        $agent_filter = '';
        unset($preserved_query['ssl_agent']);
        $group_mode = 'cn';
        $preserved_query['ssl_group'] = 'cn';
        $table_data = $this->fetch_certificates([
            'page' => $current_page,
            'per_page' => $requested_per_page,
            'search' => $search,
            'source' => $source_filter,
            'agent_only' => $agent_filter,
            'orderby' => $sort,
            'order' => $order,
        ]);
        $rows = $table_data['rows'];
        $total_found = $table_data['total'];
        $total_pages = max(1, (int)ceil($total_found / $requested_per_page));
        $is_create_hidden = empty($_GET['ssl_new']);
        $create_attr = $is_create_hidden ? ' hidden' : '';
        $admin_email = sanitize_email(get_option('admin_email'));
        $export_url = esc_url(site_url('?ssl_action='.self::EXPORT_ACTION));
        $refresh_url = esc_url(remove_query_arg('ssl_new'));
        $manager_classes = 'ssl-manager ssl-manager--compact';
        ob_start();
        echo "<div class='".esc_attr($manager_classes)."'>";
        echo "<div class='ssl-manager__header'>";
        echo "<div class='ssl-manager__title'><h2>ניהול תאריכי תפוגת דומיינים</h2>";
        if ($admin_email) {
            echo "<div class='ssl-manager__subtitle'>".esc_html($admin_email)."</div>";
        }
        echo "</div>";
        echo "<div class='ssl-manager__header-actions'>";
        echo "<a class='ssl-btn ssl-btn-primary' data-ssl-toggle='create' href='".esc_url(add_query_arg('ssl_new','1'))."'>הוסף רשומה</a>";
        echo "<a class='ssl-btn ssl-btn-outline' href='".esc_url($a['trash_url'])."'>סל מחזור</a>";
        echo "<a class='ssl-btn ssl-btn-outline' href='".esc_url($a['token_url'])."'>ניהול טוקנים</a>";
        echo "<a class='ssl-btn ssl-btn-outline' href='".esc_url($a['logs_url'])."'>לוג פעילות</a>";
        echo "<form class='ssl-page-size' method='get'>";
        foreach($preserved_query as $key => $value){
            if(in_array($key, ['ssl_per_page','ssl_page'], true)){
                continue;
            }
            echo "<input type='hidden' name='".esc_attr($key)."' value='".esc_attr($value)."'>";
        }
        echo "<input type='hidden' name='ssl_page' value='1' data-ssl-page-input>";
        echo "<label>הצג<select name='ssl_per_page' data-ssl-page-size>";
        foreach($per_page_choices as $choice){
            $label = number_format_i18n($choice);
            $selected = selected($requested_per_page, $choice, false);
            echo "<option value='".esc_attr($choice)."'{$selected}>".esc_html($label).'  רשומות לדף' ."</option>";
        }
        echo "</select></label>";
        echo "<noscript><button class='ssl-btn ssl-btn-outline' type='submit'>עדכן</button></noscript>";
        echo "</form>";
        echo "</div></div>";

        echo "<div class='ssl-card ssl-card--form' data-ssl-create{$create_attr}>";
        echo "<div class='ssl-card__header'><h3>הוספת רשומה חדשה</h3><button type='button' class='ssl-btn ssl-btn-ghost' data-ssl-toggle='create' title='סגירת הטופס' aria-label='סגירת הטופס'>&#10005;</button></div>";
        echo "<form method='post' action='".esc_url(admin_url('admin-post.php'))."' enctype='multipart/form-data'>".$this->nonce_field().""
              ."  <input type='hidden' name='action' value='".esc_attr(self::SAVE_ACTION)."' />"
              ."  <input type='hidden' name='post_id' value='0' />"
              ."  <div class='ssl-card__body'>"
              ."    <label>שם הלקוח<input type='text' name='client_name' required></label>"
              ."    <label>אתר (URL)<input type='url' name='site_url' placeholder='https://example.com'></label>"
              ."    <label>תאריך תפוגה (DD-MM-YYYY) <input type='text' name='expiry_date' placeholder='31-12-2026'></label>"
              ."    <label>ליקוט <select name='source'><option value='auto' selected>Auto</option><option value='manual'>Manual</option><option value='agent'>Agent</option></select></label>"
              ."    <label>CN של התעודה<input type='text' name='cert_cn' placeholder='*.example.com'></label>"
              ."    <label>הערות<textarea name='notes' rows='3'></textarea></label>"
              ."    <label>תמונות<input type='file' name='images[]' multiple accept='image/*'></label>"
              ."  </div>"
              ."  <div class='ssl-card__footer'><button class='ssl-btn ssl-btn-primary' type='submit'>שמור</button></div>"
              ."</form>"
              ."</div>";

        $preview_key = isset($preserved_query['ssl_preview']) ? sanitize_key($preserved_query['ssl_preview']) : '';
        if($preview_key){
            $preview_data = get_transient('ssl_import_'.$preview_key);
            $cancel_url = esc_url(remove_query_arg('ssl_preview'));
            echo "<div class='ssl-card ssl-card--form'>";
            echo "<div class='ssl-card__header'><h3>תצוגה מקדימה לייבוא</h3><a class='ssl-btn ssl-btn-ghost' href='{$cancel_url}'>בטל</a></div>";
            if($preview_data && !empty($preview_data['rows'])){
                $preview_rows = array_slice($preview_data['rows'], 0, 10);
                $total_preview = isset($preview_data['total']) ? (int)$preview_data['total'] : count($preview_data['rows']);
                $file_label = !empty($preview_data['filename']) ? esc_html($preview_data['filename']) : 'קובץ לא מזוהה';
                echo "<div class='ssl-card__body'>";
                echo "<p>קובץ: {$file_label}. יוצגו עד 10 שורות מתוך ".esc_html(number_format_i18n($total_preview)).".</p>";
                echo "<table class='ssl-table'><thead><tr><th>לקוח</th><th>אתר</th><th>CN</th><th>תוקף</th></tr></thead><tbody>";
                foreach($preview_rows as $row){
                    $client_p = esc_html($row['client_name']);
                    $site_p = esc_html($row['site_url']);
                    $cn_p = $row['common_name'] ? esc_html($row['common_name']) : '—';
                    $expiry_display = '—';
                    if(!empty($row['expiry_date'])){
                        $preview_ts = $this->parse_user_date($row['expiry_date']);
                        if($preview_ts){
                            $expiry_display = esc_html($this->fmt_date($preview_ts));
                        } else {
                            $expiry_display = esc_html($row['expiry_date']);
                        }
                    }
                    echo "<tr><td>{$client_p}</td><td>{$site_p}</td><td>{$cn_p}</td><td>{$expiry_display}</td></tr>";
                }
                if(empty($preview_rows)){
                    echo "<tr><td colspan='5' class='ssl-empty'>לא נמצאו שורות בתצוגה מקדימה</td></tr>";
                }
                echo "</tbody></table>";
                if($total_preview > count($preview_rows)){
                    echo "<div class='ssl-note'>קיימות שורות נוספות שייכללו בייבוא.</div>";
                }
                echo "</div>";
                echo "<div class='ssl-card__footer'>";
                echo "<form method='post' action='".esc_url(admin_url('admin-post.php'))."'>".$this->nonce_field()
                    ."<input type='hidden' name='action' value='".esc_attr(self::IMPORT_ACTION)."'>"
                    ."<input type='hidden' name='ssl_import_step' value='confirm'>"
                    ."<input type='hidden' name='preview_key' value='".esc_attr($preview_key)."'>"
                    ."<button class='ssl-btn ssl-btn-primary' type='submit'>אשר ייבוא</button>"
                    ."</form>";
                echo "<a class='ssl-btn ssl-btn-outline' href='{$cancel_url}'>בטל תצוגה מקדימה</a>";
                echo "</div>";
            } else {
                echo "<div class='ssl-card__body'><p>התצוגה המקדימה אינה זמינה או שפג תוקפה.</p></div>";
                echo "<div class='ssl-card__footer'><a class='ssl-btn ssl-btn-outline' href='{$cancel_url}'>חזרה</a></div>";
            }
            echo "</div>";
        }

        echo "<div class='ssl-toolbar ssl-toolbar--filters'>";
        echo "  <form class='ssl-toolbar__group' method='get' data-ssl-filter-form>";
        foreach($preserved_query as $key => $value){
            if(in_array($key, ['ssl_search','ssl_page','ssl_group'], true)){
                continue;
            }
            echo "<input type='hidden' name='".esc_attr($key)."' value='".esc_attr($value)."'>";
        }
        echo "    <input type='hidden' name='ssl_page' value='1'>";
        echo "    <input type='hidden' name='ssl_group' value='cn'>";
        echo "    <label>חיפוש<input type='search' name='ssl_search' value='".esc_attr($search)."' placeholder='חפש לקוח, דומיין או CN' data-ssl-filter-search></label>";
        echo "  </form>";
        echo "</div>";

        $header_columns = [
            ['key' => 'client_name', 'label' => 'שם הלקוח', 'sortable' => true],
            ['key' => 'site_url', 'label' => 'אתר', 'sortable' => true],
            ['key' => 'common_name', 'label' => 'CN', 'sortable' => true],
            ['key' => 'expiry_ts', 'label' => 'תאריך תפוגה', 'sortable' => true],
            ['key' => 'days', 'label' => 'ימים', 'sortable' => false],
            ['key' => 'source', 'label' => 'ליקוט', 'sortable' => true],
            ['key' => 'actions', 'label' => 'פעולות', 'sortable' => false],
        ];
        echo "<table class='ssl-table'><thead><tr>";
        foreach($header_columns as $col){
            echo "<th>";
            if(!empty($col['sortable'])){
                echo $this->build_sort_link($col['key'], $col['label'], $sort, $order, $preserved_query);
            } else {
                echo esc_html($col['label']);
            }
            echo "</th>";
        }
        echo "</tr></thead><tbody>";

        if(!empty($rows)){
            $grouped_rows = [];
            if($group_mode === 'cn'){
                foreach($rows as $row){
                    $key = $row['common_name'] !== '' ? $row['common_name'] : 'ללא CN';
                    if(!isset($grouped_rows[$key])){
                        $grouped_rows[$key] = [
                            'key' => $key,
                            'rows' => [],
                        ];
                    }
                    $grouped_rows[$key]['rows'][] = $row;
                }
                $group_sequence = array_values($grouped_rows);
            } else {
                $group_sequence = [];
                foreach($rows as $row){
                    $group_sequence[] = [
                        'key' => 'row-'.$row['post_id'],
                        'rows' => [$row],
                    ];
                }
            }
            foreach($group_sequence as $group_index => $group){
                $group_id = 'group-'.md5($group['key'].$group_index);
                $total_in_group = count($group['rows']);
                foreach($group['rows'] as $row_index => $row){
                    $id = (int)$row['post_id'];
                    $client = $row['client_name'];
                    $url = $row['site_url'];
                    $cn = $row['common_name'];
                    $expiry = !empty($row['expiry_ts']) ? (int)$row['expiry_ts'] : 0;
                    $src = $row['source'];
                    $notes = $row['notes'];
                    $err = $row['last_error'];
                    $imgs = $row['images'];
                    $days = $this->days_left($expiry);
                    $badge = $this->badge_class($days);
                    $days_txt = $days === null ? '' : $days;
                    if($src === 'agent'){
                        $src_label = 'Agent';
                    } elseif($src === 'auto'){
                        $src_label = 'Auto';
                    } else {
                        $src_label = 'Manual';
                    }
                    $cn_label = $cn !== '' ? $cn : '—';
                    if($cn && strpos($cn, '*.') === 0){
                        $cn_label .= ' (Wildcard)';
                    }
                    $row_attrs = '';
                    if($group_mode === 'cn' && $total_in_group > 1 && $row_index > 0){
                        $row_attrs = " data-ssl-group-child='".esc_attr($group_id)."' hidden";
                    } elseif($group_mode === 'cn' && $total_in_group > 1){
                        $row_attrs = " data-ssl-group-parent='".esc_attr($group_id)."'";
                    }
                    echo "<tr{$row_attrs}>";
                    $client_cell = esc_html($client);
                    if($group_mode === 'cn' && $total_in_group > 1 && $row_index === 0){
                        $toggle_label = $total_in_group.' רשומות';
                        $client_cell = "<button type='button' class='ssl-btn ssl-btn-ghost ssl-group-toggle' data-ssl-group-toggle='".esc_attr($group_id)."' aria-expanded='false'>+</button>".$client_cell."<div class='ssl-group-meta'>".esc_html($toggle_label)."</div>";
                    }
                    echo "<td>{$client_cell}</td>";
                    $link = $url ? "<a target='_blank' rel='noopener' href='".esc_url($url)."'>".esc_html($url)."</a>" : '—';
                    echo "<td>{$link}</td>";
                    echo "<td>".esc_html($cn_label)."</td>";
                    echo "<td>".$this->fmt_date($expiry)."</td>";
                    echo "<td><span class='ssl-badge {$badge}'>".esc_html($days_txt)."</span></td>";
                    echo "<td>".esc_html($src_label)."</td>";
                    $actions = "<a class='ssl-btn ssl-btn-surface' href='javascript:void(0)' data-ssl-edit='".esc_attr($id)."'>עריכה</a>";
                    $del_url = esc_url(admin_url('admin-post.php'));
                    $actions .= "<form method='post' action='{$del_url}'>".$this->nonce_field()
                        ."<input type='hidden' name='action' value='".esc_attr(self::DELETE_ACTION)."' />"
                        ."<input type='hidden' name='post_id' value='".esc_attr($id)."' />"
                        ."<button class='ssl-btn ssl-btn-danger' type='submit' onclick=\"return confirm('להעביר לסל מחזור?')\">מחיקה</button>"
                        ."</form>";
                    echo "<td class='ssl-actions'>{$actions}</td>";
                    echo "</tr>";

                    $detail_attrs = '';
                    if($group_mode === 'cn' && $total_in_group > 1){
                        $detail_attrs = " data-ssl-group-child='".esc_attr($group_id)."'";
                        if($row_index > 0){
                            $detail_attrs .= ' hidden';
                        }
                    }
                    $notes_html = $notes !== '' ? nl2br(esc_html($notes)) : '—';
                    $images_markup = '';
                    if(!empty($imgs)){
                        foreach($imgs as $aid){
                            $aid = (int)$aid;
                            if(!$aid){
                                continue;
                            }
                            $thumb = wp_get_attachment_image_url($aid,'thumbnail');
                            $full = wp_get_attachment_url($aid);
                            if($thumb){
                                $full = $full ? esc_url($full) : esc_url($thumb);
                                $images_markup .= "<a target='_blank' href='{$full}'><img src='".esc_url($thumb)."' alt='' /></a>";
                            }
                        }
                    }
                    if($images_markup === ''){
                        $images_markup = '<span class="ssl-note">—</span>';
                    } else {
                        $images_markup = "<div class='ssl-row-details__images'>{$images_markup}</div>";
                    }
                    $error_markup = $err ? "<span class='ssl-row-details__error'>".esc_html($err)."</span>" : '<span class="ssl-note">—</span>';
                    $details_html = "<div class='ssl-row-details__wrap'>"
                        ."<div class='ssl-row-details__section'><h4>הערות</h4><div>{$notes_html}</div></div>"
                        ."<div class='ssl-row-details__section'><h4>תמונות</h4>{$images_markup}</div>"
                        ."<div class='ssl-row-details__section'><h4>שגיאה</h4>{$error_markup}</div>"
                        ."</div>";
                    echo "<tr class='ssl-row-details'{$detail_attrs}><td colspan='7'>{$details_html}</td></tr>";

                    echo "<tr data-ssl-form='".esc_attr($id)."' class='ssl-table__edit-row' hidden><td colspan='7'><div class='ssl-card ssl-card--form'>"
                        ."<div class='ssl-card__header'><h3>עריכת רשומה</h3><button type='button' class='ssl-btn ssl-btn-ghost' data-ssl-edit='".esc_attr($id)."' title='סגירת עריכה' aria-label='סגירת עריכה'>&#10005;</button></div>"
                        ."<form method='post' action='".esc_url(admin_url('admin-post.php'))."' enctype='multipart/form-data'>".$this->nonce_field()
                        ."<input type='hidden' name='action' value='".esc_attr(self::SAVE_ACTION)."' />"
                        ."<input type='hidden' name='post_id' value='".esc_attr($id)."' />"
                        ."<div class='ssl-card__body'>"
                        ."<label>שם הלקוח<input type='text' name='client_name' value='".esc_attr($client)."'></label>"
                        ."<label>אתר (URL)<input type='url' name='site_url' value='".esc_attr($url)."'></label>"
                        ."<label>תאריך תפוגה (DD-MM-YYYY) <input type='text' name='expiry_date' value='".esc_attr($this->fmt_date($expiry))."'></label>"
                        ."<label>ליקוט <select name='source'><option value='auto' ".selected($src,'auto',false).">Auto</option><option value='manual' ".selected($src,'manual',false).">Manual</option><option value='agent' ".selected($src,'agent',false).">Agent</option></select></label>"
                        ."<label>CN של התעודה<input type='text' name='cert_cn' value='".esc_attr($cn)."'></label>"
                        ."<label>הערות<textarea name='notes' rows='3'>".esc_textarea($notes)."</textarea></label>"
                        ."<label>תמונות (להוסיף חדשות) <input type='file' name='images[]' multiple accept='image/*'></label>"
                        ."</div>"
                        ."<div class='ssl-card__footer'><button class='ssl-btn ssl-btn-primary' type='submit'>שמור</button></div>"
                        ."</form>"
                        ."</div></td></tr>";
                }
            }
        } else {
            echo "<tr><td class='ssl-empty' colspan='7'>אין נתונים</td></tr>";
        }
        echo "</tbody></table>";

        if($total_pages > 1){
            $pagination_args = [];
            foreach($preserved_query as $key => $value){
                if($key === 'ssl_page'){
                    continue;
                }
                $pagination_args[$key] = $value;
            }
            $pagination_args['ssl_per_page'] = $requested_per_page;
            $base_url = remove_query_arg('ssl_page', add_query_arg([]));
            $links = paginate_links([
                'base'      => add_query_arg('ssl_page', '%#%', $base_url),
                'format'    => '',
                'current'   => $current_page,
                'total'     => $total_pages,
                'type'      => 'array',
                'add_args'  => $pagination_args,
                'prev_text' => '&laquo; הקודם',
                'next_text' => 'הבא &raquo;',
            ]);
            if(!empty($links)){
                echo "<div class='ssl-pagination'><ul class='ssl-pagination__list'>";
                foreach($links as $link){
                    echo "<li class='ssl-pagination__item'>".$link."</li>";
                }
                echo "</ul></div>";
            }
        }
        echo "<div class='ssl-note'>נמצאו " . esc_html(number_format_i18n($total_found)) . " רשומות. צבעים: ירוק &gt; 90, צהוב 31–90, אדום ≤ 30.</div>";
        echo "<div class='ssl-footer-tools'>";
        echo "  <div class='ssl-toolbar ssl-toolbar--bottom'>";
        echo "    <div class='ssl-toolbar__group'><a class='ssl-btn ssl-btn-surface' href='{$export_url}'>ייצוא CSV</a>";
        echo "    <a class='ssl-btn ssl-btn-surface' href='{$refresh_url}'>רענון</a></div>";
        echo "    <form class='ssl-toolbar__import' method='post' action='".esc_url(admin_url('admin-post.php'))."' enctype='multipart/form-data'>".$this->nonce_field()
             ."      <input type='hidden' name='action' value='".esc_attr(self::IMPORT_ACTION)."' />"
             ."      <input type='hidden' name='ssl_import_step' value='preview' />"
             ."      <input type='file' name='import_file' accept='.csv,.xlsx' required />"
             ."      <button class='ssl-btn ssl-btn-primary' type='submit'>תצוגה מקדימה לייבוא</button>"
             ."    </form>";
        echo "    <div class='ssl-toolbar__group ssl-toolbar__group--end'><span class='ssl-note'>ייבוא תומך ב-CSV וב-Excel (כולל עברית).</span></div>";
        echo "  </div>";
        echo "</div>";
        echo "</div>";
        return ob_get_clean();
    }
    public function shortcode_trash($atts = []) {
        $main_default = $this->resolve_main_page_url();
        $logs_default = $this->resolve_logs_page_url();
        $a = shortcode_atts([
            'main_url' => $main_default,
            'logs_url' => $logs_default,
        ], $atts);
        $q = new WP_Query(['post_type'=> self::CPT,'post_status'=> 'trash','posts_per_page'=> -1,'orderby'=>'modified','order'=>'DESC']);
        ob_start();
        echo "<div class='ssl-manager'>";
        echo "<div class='ssl-manager__header'>";
        echo "<div class='ssl-manager__title'><h2>סל מחזור</h2><div class='ssl-manager__subtitle'>רשומות שנמחקו נשמרות למשך 90 יום לפני מחיקה סופית.</div></div>";
        echo "<div class='ssl-manager__header-actions'>";
        echo "<a class='ssl-btn ssl-btn-outline' href='".esc_url($a['main_url'])."'>חזרה לטבלה</a>";
        echo "<a class='ssl-btn ssl-btn-outline' href='".esc_url($a['logs_url'])."'>לוג פעילות</a>";
        echo "</div>";
        echo "</div>";
        echo "<table class='ssl-table'><thead><tr><th>שם הלקוח</th><th>אתר</th><th>נמחק</th><th>שחזור</th></tr></thead><tbody>";
        if ($q->have_posts()){
            while($q->have_posts()){ $q->the_post();
                $id=get_the_ID(); $url=get_post_meta($id,'site_url',true);
                echo "<tr><td>".esc_html(get_post_meta($id,'client_name',true))."</td>
                          <td>".esc_html($url)."</td>
                          <td>".esc_html(get_the_modified_date('Y-m-d'))."</td>
                          <td><form method='post' action='".esc_url(admin_url('admin-post.php'))."' class='ssl-actions'>".$this->nonce_field()."
                                <input type='hidden' name='action' value='".esc_attr(self::RESTORE_ACTION)."' />
                                <input type='hidden' name='post_id' value='".esc_attr($id)."' />
                                <button class='ssl-btn ssl-btn-primary' type='submit'>שחזר</button>
                              </form></td></tr>";
            }
            wp_reset_postdata();
        } else {
            echo "<tr><td class='ssl-empty' colspan='4'>אין רשומות בסל המחזור</td></tr>";
        }
        echo "</tbody></table>";
        echo "</div>";
        return ob_get_clean();
    }

    public function shortcode_controls($atts = []) {
        $main_default = $this->resolve_main_page_url();
        $default_token = $this->resolve_token_page_url();
        $default_trash = $this->resolve_trash_page_url();
        $default_logs  = $this->resolve_logs_page_url();
        $a = shortcode_atts([
            'main_url'=>$main_default,
            'trash_url'=>$default_trash,
            'token_url'=>$default_token,
            'logs_url'=>$default_logs,
        ], $atts);
        $export_url = site_url('?ssl_action='.self::EXPORT_ACTION);
        $import_action = esc_attr(self::IMPORT_ACTION);
        ob_start();
        echo "<div class='ssl-manager'>";
        echo "<div class='ssl-manager__header'>";
        echo "<div class='ssl-manager__title'><h2>פעולות מהירות</h2><div class='ssl-manager__subtitle'>ניהול זריז של רשומות SSL</div></div>";
        echo "<div class='ssl-manager__header-actions'>";
        echo "<a class='ssl-btn ssl-btn-primary' href='".esc_url(add_query_arg('ssl_new','1',$a['main_url']))."'>הוסף רשומה</a>";
        echo "<a class='ssl-btn ssl-btn-outline' href='".esc_url($a['trash_url'])."'>סל מחזור</a>";
        echo "<a class='ssl-btn ssl-btn-outline' href='".esc_url($a['token_url'])."'>ניהול טוקנים</a>";
        echo "<a class='ssl-btn ssl-btn-outline' href='".esc_url($a['logs_url'])."'>לוג פעילות</a>";
        echo "</div></div>";
        echo "<div class='ssl-toolbar'>";
        echo "<div class='ssl-toolbar__group'><a class='ssl-btn ssl-btn-surface' href='".esc_url($export_url)."'>ייצוא CSV</a>";
        echo "<a class='ssl-btn ssl-btn-surface' href='".esc_url($a['main_url'])."'>לטבלה הראשית</a></div>";
        echo "<form class='ssl-toolbar__import' method='post' action='".esc_url(admin_url('admin-post.php'))."' enctype='multipart/form-data'>".$this->nonce_field().""
                ."<input type='hidden' name='action' value='{$import_action}' />"
                ."<input type='hidden' name='ssl_import_step' value='preview' />"
                ."<input type='file' name='import_file' accept='.csv,.xlsx' required />"
                ."<button class='ssl-btn ssl-btn-primary' type='submit'>תצוגה מקדימה לייבוא</button>"
              ."</form>";
        echo "</div>";
        echo "</div>";
        return ob_get_clean();
    }
    public function shortcode_token() {
        $tokens = $this->ensure_default_token();
        $token  = $tokens[0];
        $action = esc_attr('ssl_regen_token');
        ob_start();
        echo "<div class='ssl-manager'>";
        echo "<div class='ssl-card'>";
        echo "<div class='ssl-card__header'><h3>".esc_html($token['name'])."</h3></div>";
        echo "<div class='ssl-card__body ssl-token-row'>";
        echo "<input class='ssl-token-input' type='text' readonly value='".esc_attr($token['token'])."'>";
        echo "<form class='ssl-token-form ssl-token-form--stack' method='post' action='".esc_url(admin_url('admin-post.php'))."'>".$this->nonce_field().""
                ."<input type='hidden' name='action' value='{$action}'>"
                ."<input type='hidden' name='token_id' value='".esc_attr($token['id'])."'>"
              ."</form>";
        echo "</div>";
        echo "<div class='ssl-note'>Header: <code>X-SSL-Token</code> = הערך לעיל</div>";
        echo "</div>";
        echo "</div>";
        return ob_get_clean();
    }
    public function shortcode_token_page($atts = []) {
        $main_default = $this->resolve_main_page_url();
        $trash_default = $this->resolve_trash_page_url();
        $logs_default  = $this->resolve_logs_page_url();
        $a = shortcode_atts([
            'main_url'  => $main_default,
            'trash_url' => $trash_default,
            'logs_url'  => $logs_default,
        ], $atts);
        $tokens = $this->ensure_default_token();
        $add_action    = esc_attr(self::ADD_TOKEN_ACTION);
        $manage_action = esc_attr(self::MANAGE_TOKEN_ACTION);
        $email_choices = $this->collect_token_email_choices();
        ob_start();
        echo "<div class='ssl-manager'>";
        echo "<div class='ssl-manager__header ssl-manager__header--tokens'>";
        echo "<div class='ssl-manager__title'>";
        echo "<h2>ניהול Tokens לסוכן SSL</h2>";
        echo "<div class='ssl-manager__subtitle'>הטוקנים הבאים זמינים לשימוש ב-Header בשם <code>X-SSL-Token</code>.</div>";
        echo "</div>";
        echo "<div class='ssl-manager__header-actions'>";
        echo "<a class='ssl-btn ssl-btn-surface' href='".esc_url($a['main_url'])."'>חזרה לטבלה הראשית</a>";
        echo "<a class='ssl-btn ssl-btn-outline' href='".esc_url($a['trash_url'])."'>מעבר לסל מחזור</a>";
        echo "<a class='ssl-btn ssl-btn-outline' href='".esc_url($a['logs_url'])."'>לוג פעילות</a>";
        echo "</div>";
        echo "</div>";

        echo "<div class='ssl-card ssl-card--form ssl-card--token-create'>";
        echo "<form class='ssl-token-create' method='post' action='".esc_url(admin_url('admin-post.php'))."'>".$this->nonce_field().""
                ."<input type='hidden' name='action' value='{$add_action}'>"
                ."<div class='ssl-token-create__fields'>"
                ."  <label><span>שם הטוקן</span><input type='text' name='token_name' placeholder='לדוגמה: סוכן ראשי' required></label>"
                ."  <button class='ssl-btn ssl-btn-primary' type='submit'>וסף טוקן</button>"
                ."</div>"
                ."<p class='ssl-note'>הוסיפו טוקנים לפי הצורך והשתמשו בערך שלהם בבקשות מרוחקות.</p>"
              ."</form>";
        echo "</div>";

        $forms = '';
        foreach($tokens as $token){
            $form_id = 'ssl-token-manage-'.sanitize_key($token['id']);
            $forms .= "<form id='".esc_attr($form_id)."' class='ssl-token-hidden-form' method='post' action='".esc_url(admin_url('admin-post.php'))."'>".$this->nonce_field().""
                    ."<input type='hidden' name='action' value='{$manage_action}'>"
                    ."<input type='hidden' name='token_id' value='".esc_attr($token['id'])."'>"
                 ."</form>";
        }
        echo $forms;

        echo "<table class='ssl-table ssl-token-table'>";
        echo "<thead><tr><th>שם הטוקן</th><th>ערך הטוקן</th><th>סטטוס חיבור</th><th>התראות</th><th>נמענים</th><th style='width:240px'>פעולות</th></tr></thead>";
        echo "<tbody>";
        if(!empty($tokens)){
            foreach($tokens as $token){
                $form_id = 'ssl-token-manage-'.sanitize_key($token['id']);
                $updated = !empty($token['updated']) ? date_i18n('d.m.Y H:i', (int)$token['updated']) : '—';
                $status = isset($token['last_status']) ? $token['last_status'] : 'unknown';
                $status_label = 'לא ידוע';
                $dot_class = 'ssl-token-status__dot--unknown';
                if($status === 'online'){
                    $status_label = 'מחובר';
                    $dot_class = 'ssl-token-status__dot--online';
                } elseif($status === 'offline'){
                    $status_label = 'מנותק';
                    $dot_class = 'ssl-token-status__dot--offline';
                }
                $last_seen_ts = !empty($token['last_seen']) ? (int)$token['last_seen'] : 0;
                $last_seen = $last_seen_ts ? date_i18n('d.m.Y H:i', $last_seen_ts) : '';
                $status_meta = [];
                if($last_seen){
                    $status_meta[] = 'חיבור אחרון: '.$last_seen;
                } else {
                    $status_meta[] = 'לא התקבלה תקשורת עדיין';
                }
                if(!empty($token['last_error']) && $status === 'offline'){
                    $status_meta[] = 'שגיאה אחרונה: '.$token['last_error'];
                }
                $status_meta[] = 'עודכן: '.$updated;
                $stored_emails = array_filter((array)($token['emails'] ?? []));
                $email_options = $email_choices;
                foreach($stored_emails as $email){
                    if($email && !isset($email_options[$email])){
                        $email_options[$email] = $email;
                    }
                }
                echo "<tr>";
                echo "<td class='ssl-token-table__name'><input form='".esc_attr($form_id)."' type='text' name='token_name' value='".esc_attr($token['name'])."' required></td>";
                echo "<td class='ssl-token-table__token'><input type='text' readonly value='".esc_attr($token['token'])."'></td>";
                echo "<td class='ssl-token-table__status'><div class='ssl-token-status'><span class='ssl-token-status__dot " .esc_attr($dot_class)."' aria-hidden='true'></span><div class='ssl-token-status__text'><div class='ssl-token-status__label'>".esc_html($status_label)."</div>";
                foreach($status_meta as $meta){
                    $is_error = (strpos($meta, 'שגיאה אחרונה') === 0);
                    $meta_class = $is_error ? ' ssl-token-status__meta--error' : '';
                    echo "<div class='ssl-token-status__meta{$meta_class}'>".esc_html($meta)."</div>";
                }
                echo "</div></div></td>";
                $checked = !empty($token['notify_down']) ? " checked" : '';
                echo "<td class='ssl-token-table__notify'><label class='ssl-token-toggle'><input form='".esc_attr($form_id)."' type='checkbox' name='notify_down' value='1'{$checked}><span>שליחת התראה בנפילה</span></label></td>";
                echo "<td class='ssl-token-table__emails'>";
                $datalist_id = 'ssl-token-email-suggest-'.sanitize_key($token['id']);
                echo "<div class='ssl-token-emails' data-email-list data-email-form='".esc_attr($form_id)."'>";
                echo "<div class='ssl-token-email-list' data-email-chips>";
                if(!empty($stored_emails)){
                    foreach($stored_emails as $email){
                        echo "<span class='ssl-token-email-chip' data-email-item>";
                        echo "<input type='hidden' form='".esc_attr($form_id)."' name='token_emails[]' value='".esc_attr($email)."'>";
                        echo "<span class='ssl-token-email-chip__text'>".esc_html($email)."</span>";
                        echo "<button type='button' class='ssl-token-email-chip__remove' data-email-remove aria-label='הסר כתובת'>×</button>";
                        echo "</span>";
                    }
                } else {
                    echo "<span class='ssl-token-email-chip ssl-token-email-chip--empty' data-email-empty>אין נמענים</span>";
                }
                echo "</div>";
                echo "<div class='ssl-token-email-add'>";
                echo "<input type='email' data-email-input list='".esc_attr($datalist_id)."' placeholder='הוספת כתובת'>";
                if(!empty($email_options)){
                    echo "<datalist id='".esc_attr($datalist_id)."'>";
                    foreach($email_options as $email => $label){
                        echo "<option value='".esc_attr($email)."' label='".esc_attr($label)."'></option>";
                    }
                    echo "</datalist>";
                }
                echo "<button type='button' class='ssl-btn ssl-btn-surface' data-email-add>הוסף</button>";
                echo "</div>";
                echo "<div class='ssl-token-email-error' data-email-error></div>";
                echo "</div>";
                echo "</td>";
                echo "<td><div class='ssl-token-table__actions'>";
                echo "<button class='ssl-btn ssl-btn-primary' type='submit' form='".esc_attr($form_id)."' name='sub_action' value='update'>שמור</button>";
                echo "<button class='ssl-btn ssl-btn-danger' type='submit' form='".esc_attr($form_id)."' name='sub_action' value='delete' onclick=\"return confirm('למחוק את הטוקן?')\">מחק</button>";
                echo "</div></td>";
                echo "</tr>";
            }
        } else {
            echo "<tr><td class='ssl-empty' colspan='6'>לא נמצאו טוקנים</td></tr>";
        }
        echo "</tbody>";
        echo "</table>";
        echo "<div class='ssl-note ssl-token-note'>הוסיפו נמענים חדשים באמצעות השדה והכפתור, והסירו כתובות בעזרת כפתור ה-X שמופיע ליד כל נמען. התראות נשלחות רק כאשר הטוקן מסומן לניטור.</div>";
        echo "</div>";
        return ob_get_clean();
    }

    public function shortcode_logs($atts = []) {
        $main_default  = $this->resolve_main_page_url();
        $trash_default = $this->resolve_trash_page_url();
        $token_default = $this->resolve_token_page_url();
        $a = shortcode_atts([
            'limit'    => 100,
            'main_url' => $main_default,
            'trash_url'=> $trash_default,
            'token_url'=> $token_default,
        ], $atts);
        $limit = absint($a['limit']);
        if($limit === 0){
            $limit = 100;
        }
        $limit = min($limit, 200);
        $log_entries = array_reverse($this->get_activity_log());
        if($limit > 0){
            $log_entries = array_slice($log_entries, 0, $limit);
        }
        ob_start();
        echo "<div class='ssl-manager'>";
        echo "<div class='ssl-manager__header'>";
        echo "<div class='ssl-manager__title'><h2>לוג פעילות הסוכן</h2><div class='ssl-manager__subtitle'>מוצגות עד ".esc_html($limit)." הרשומות האחרונות.</div></div>";
        echo "<div class='ssl-manager__header-actions'>";
        echo "<a class='ssl-btn ssl-btn-outline' href='".esc_url($a['main_url'])."'>חזרה לטבלה</a>";
        echo "<a class='ssl-btn ssl-btn-outline' href='".esc_url($a['trash_url'])."'>סל מחזור</a>";
        echo "<a class='ssl-btn ssl-btn-outline' href='".esc_url($a['token_url'])."'>ניהול טוקנים</a>";
        echo "</div>";
        echo "</div>";
        if(empty($log_entries)){
            echo "<div class='ssl-empty'>לא נמצאו רשומות פעילות עדיין.</div>";
        } else {
            echo "<table class='ssl-table ssl-log-table'><thead><tr><th>זמן</th><th>רמה</th><th>תיאור</th><th>פרטים</th></tr></thead><tbody>";
            foreach($log_entries as $entry){
                $time = !empty($entry['time']) ? date_i18n('Y-m-d H:i:s', (int)$entry['time']) : '';
                $raw_level = strtolower(is_string($entry['level'] ?? '') ? $entry['level'] : '');
                if(!in_array($raw_level, ['info','warning','error'], true)){
                    $raw_level = 'info';
                }
                $level_label = strtoupper($raw_level);
                $message = esc_html($entry['message'] ?? '');
                $context_html = $this->format_log_context_display($entry['context'] ?? []);
                echo "<tr>";
                echo "<td class='ssl-log-table__time'>".esc_html($time)."</td>";
                echo "<td class='ssl-log-table__level'><span class='ssl-log-level ssl-log-level--".esc_attr($raw_level)."'>".esc_html($level_label)."</span></td>";
                echo "<td class='ssl-log-table__message'>".$message."</td>";
                echo "<td class='ssl-log-table__context'>".$context_html."</td>";
                echo "</tr>";
            }
            echo "</tbody></table>";
        }
        echo "</div>";
        return ob_get_clean();
    }
    public function handle_regen_token() {
        $this->check_nonce();
        $tokens = $this->ensure_default_token();
        $token_id = sanitize_text_field($_POST['token_id'] ?? '');
        if(!$token_id && !empty($tokens)){
            $token_id = $tokens[0]['id'];
        }
        $updated = false;
        $token_name = '';
        foreach($tokens as &$token){
            if($token['id'] === $token_id){
                $token_name = $token['name'];
                $token['token'] = $this->generate_token_value();
                $token['updated'] = time();
                $token['last_status'] = 'unknown';
                $token['last_seen'] = 0;
                $token['last_error'] = '';
                $token['notified_down_at'] = 0;
                $updated = true;
                break;
            }
        }
        unset($token);
        if($updated){
            $this->save_tokens($tokens);
            $this->log_activity('טוקן אופס מחדש', array_merge([
                'token_id' => $token_id,
                'token_name' => $token_name,
            ], $this->get_current_actor_context()));
        }
        wp_safe_redirect( wp_get_referer() ?: home_url('/') ); exit;
    }

    public function handle_add_token(){
        $this->check_nonce();
        $tokens = $this->get_tokens();
        $name = sanitize_text_field($_POST['token_name'] ?? '');
        if($name === ''){
            $name = 'ללא שם';
        }
        $new_token = [
            'id'      => $this->generate_token_id(),
            'name'    => $name,
            'token'   => $this->generate_token_value(),
            'created' => time(),
            'updated' => time(),
            'last_status' => 'unknown',
            'last_seen'   => 0,
            'last_error'  => '',
            'notify_down' => 0,
            'emails'      => [],
            'notified_down_at' => 0,
        ];
        $tokens[] = $new_token;
        $this->save_tokens($tokens);
        $this->log_activity('טוקן חדש נוצר', array_merge([
            'token_id' => $new_token['id'],
            'token_name' => $new_token['name'],
        ], $this->get_current_actor_context()));
        wp_safe_redirect( wp_get_referer() ?: home_url('/') ); exit;
    }

    public function handle_manage_token(){
        $this->check_nonce();
        $tokens = $this->get_tokens();
        $token_id = sanitize_text_field($_POST['token_id'] ?? '');
        $sub = sanitize_key($_POST['sub_action'] ?? 'update');
        $name = sanitize_text_field($_POST['token_name'] ?? '');
        if($name === ''){
            $name = 'ללא שם';
        }
        $notify = !empty($_POST['notify_down']) ? 1 : 0;
        $emails = $this->parse_token_emails($_POST['token_emails'] ?? [], $_POST['token_emails_extra'] ?? '');
        $changed = false;
        $log_action = '';
        $log_context = [];
        foreach($tokens as $index => &$token){
            if($token['id'] !== $token_id){
                continue;
            }
            if($sub === 'delete'){
                $log_action = 'delete';
                $log_context = [
                    'token_id' => $token['id'],
                    'token_name' => $token['name'],
                ];
                unset($tokens[$index]);
                $changed = true;
                break;
            }
            if(in_array($sub, ['regen','update'], true)){
                $log_action = $sub === 'regen' ? 'regen' : 'update';
                $token['name'] = $name;
                $token['notify_down'] = $notify;
                $token['emails'] = $emails;
                if(!$notify){
                    $token['notified_down_at'] = 0;
                }
                if($sub === 'regen'){
                    $token['token'] = $this->generate_token_value();
                    $token['last_status'] = 'unknown';
                    $token['last_seen'] = 0;
                    $token['last_error'] = '';
                    $token['notified_down_at'] = 0;
                }
                $token['updated'] = time();
                $log_context = [
                    'token_id' => $token['id'],
                    'token_name' => $token['name'],
                    'notify_down' => (bool)$notify,
                    'emails' => $emails,
                ];
                if($sub === 'regen'){
                    $log_context['regenerated'] = true;
                }
                $changed = true;
            }
            break;
        }
        unset($token);
        if($changed){
            $tokens = array_values($tokens);
            if(empty($tokens)){
                $default_token = [
                    'id'      => $this->generate_token_id(),
                    'name'    => 'Token ראשי',
                    'token'   => $this->generate_token_value(),
                    'created' => time(),
                    'updated' => time(),
                    'last_status' => 'unknown',
                    'last_seen'   => 0,
                    'last_error'  => '',
                    'notify_down' => 0,
                    'emails'      => [],
                    'notified_down_at' => 0,
                ];
                $tokens[] = $default_token;
                $this->log_activity('נוצר טוקן ברירת מחדל חדש', array_merge([
                    'token_id' => $default_token['id'],
                    'token_name' => $default_token['name'],
                ], $this->get_current_actor_context()));
            }
            $this->save_tokens($tokens);
            if($log_action){
                $messages = [
                    'delete' => 'טוקן נמחק',
                    'regen'  => 'טוקן אופס מחדש',
                    'update' => 'טוקן עודכן',
                ];
                $message = $messages[$log_action] ?? 'שינוי טוקן';
                $this->log_activity($message, array_merge($log_context, $this->get_current_actor_context()));
            }
        }
        wp_safe_redirect( wp_get_referer() ?: home_url('/') ); exit;
    }

    public function handle_save_remote_client(){
        if(!current_user_can('manage_options')){
            wp_die('אין לך הרשאה לעדכן הגדרות אלו');
        }
        check_admin_referer('ssl_remote_client');
        $enabled = !empty($_POST['remote_enabled']) ? 1 : 0;
        $local_fallback = !empty($_POST['remote_local_fallback']) ? 1 : 0;
        $settings = [
            'enabled' => $enabled,
            'local_fallback' => $local_fallback,
        ];
        update_option(self::OPTION_REMOTE, $settings);
        $this->log_activity('עודכנו הגדרות הסוכן המרוחק', array_merge($settings, $this->get_current_actor_context()));
        $redirect = add_query_arg([
            'page' => 'ssl-expiry-api',
            'remote-updated' => 1,
        ], admin_url('options-general.php'));
        wp_safe_redirect($redirect);
        exit;
    }

    public function handle_save() {
        $this->check_nonce();
        $post_id=intval($_POST['post_id'] ?? 0);
        $is_new = $post_id ? false : true;
        $client=sanitize_text_field($_POST['client_name'] ?? '');
        $site=$this->sanitize_url($_POST['site_url'] ?? '');
        $expiry_date=sanitize_text_field($_POST['expiry_date'] ?? '');
        $source = $this->normalize_source_value($_POST['source'] ?? 'auto', 'auto');
        $notes=sanitize_textarea_field($_POST['notes'] ?? '');
        $cert_cn = sanitize_text_field($_POST['cert_cn'] ?? '');
        $agent_only = !empty($_POST['agent_only']) ? 1 : 0;

        $expiry_ts = $this->parse_user_date($expiry_date);

        if($post_id){ wp_update_post(['ID'=>$post_id,'post_title'=>$client?:'SSL Item']); }
        else { $post_id=wp_insert_post(['post_type'=>self::CPT,'post_status'=>'publish','post_title'=>$client?:'SSL Item']); }

        if($post_id && !is_wp_error($post_id)){
            update_post_meta($post_id,'client_name',$client);
            update_post_meta($post_id,'site_url',$site);
            if($expiry_ts) update_post_meta($post_id,'expiry_ts',$expiry_ts);
            update_post_meta($post_id,'source',$source);
            update_post_meta($post_id,'notes',$notes);
            update_post_meta($post_id,'agent_only',$agent_only);
            update_post_meta($post_id,'cert_cn',$cert_cn);

            $dispatched = false;
            $fallback_used = false;
            $cert_details = null;
            if($site && ($cert_cn === '' || !$expiry_ts)){
                $cert_details = $this->fetch_ssl_certificate_details($site);
                if($cert_details){
                    if($cert_cn === '' && !empty($cert_details['common_name'])){
                        $resolved_cn = sanitize_text_field($cert_details['common_name']);
                        update_post_meta($post_id,'cert_cn',$resolved_cn);
                        $cert_cn = $resolved_cn;
                    }
                    if(!$expiry_ts && !empty($cert_details['expiry_ts'])){
                        $resolved_expiry = (int)$cert_details['expiry_ts'];
                        update_post_meta($post_id,'expiry_ts',$resolved_expiry);
                        $expiry_ts = $resolved_expiry;
                    }
                }
            }
            if(!empty($_FILES['images']) && is_array($_FILES['images']['name'])){
                $ids=get_post_meta($post_id,'images',true); if(!is_array($ids)) $ids=[];
                $f=$_FILES['images'];
                for($i=0;$i<count($f['name']);$i++){
                    if($f['error'][$i]===UPLOAD_ERR_OK && $f['size'][$i]>0){
                        $fa=['name'=>sanitize_file_name($f['name'][$i]),'type'=>$f['type'][$i],'tmp_name'=>$f['tmp_name'][$i],'error'=>0,'size'=>$f['size'][$i]];
                        $move=wp_handle_upload($fa,['test_form'=>false]);
                        if($move && empty($move['error'])){
                            $att=['post_mime_type'=>$move['type'],'post_title'=>sanitize_file_name($fa['name']),'post_status'=>'inherit'];
                            $aid=wp_insert_attachment($att,$move['file'],$post_id);
                            require_once(ABSPATH.'wp-admin/includes/image.php');
                            $meta=wp_generate_attachment_metadata($aid,$move['file']);
                            wp_update_attachment_metadata($aid,$meta);
                            $ids[]=$aid;
                        }
                    }
                }
                update_post_meta($post_id,'images',$ids);
            }
            if($site){
                $settings = $this->get_remote_client_settings();
                if($this->dispatch_remote_check($post_id, $site, 'manual-save', $settings)){
                    $dispatched = true;
                } elseif(!empty($settings['local_fallback'])){
                    if($cert_details === null){
                        $cert_details = $this->fetch_ssl_certificate_details($site);
                    }
                    if($cert_details){
                        if(!empty($cert_details['expiry_ts'])){
                            update_post_meta($post_id,'expiry_ts',(int)$cert_details['expiry_ts']);
                            $expiry_ts = (int)$cert_details['expiry_ts'];
                        }
                        if(!empty($cert_details['common_name'])){
                            $resolved_cn = sanitize_text_field($cert_details['common_name']);
                            update_post_meta($post_id,'cert_cn',$resolved_cn);
                            $cert_cn = $resolved_cn;
                        }
                        update_post_meta($post_id,'source',$this->normalize_source_value('auto'));
                        $source = 'auto';
                        delete_post_meta($post_id,'last_error');
                        $fallback_used = true;
                    }
                }
            }
            $this->log_activity($is_new ? 'נוצרה רשומת SSL חדשה' : 'עודכנה רשומת SSL קיימת', array_merge([
                'id' => $post_id,
                'client_name' => $client,
                'site_url' => $site,
                'common_name' => $cert_cn,
                'source' => $source,
                'agent_only' => (bool)$agent_only,
                'dispatched_to_agent' => $dispatched,
                'local_fallback_used' => $fallback_used,
            ], $this->get_current_actor_context()));
            $this->sync_table_record($post_id, get_post_status($post_id));
        }
        wp_safe_redirect( wp_get_referer() ?: home_url('/') ); exit;
    }
    public function handle_delete(){
        $this->check_nonce();
        $id=intval($_POST['post_id']??0);
        if($id){
            $post = get_post($id);
            $client = get_post_meta($id,'client_name',true);
            $site = get_post_meta($id,'site_url',true);
            $cn = get_post_meta($id,'cert_cn',true);
            wp_trash_post($id);
            $this->log_activity('רשומת SSL הועברה לסל המחזור', array_merge([
                'id' => $id,
                'client_name' => $client,
                'site_url' => $site,
                'common_name' => $cn,
                'post_title' => $post ? $post->post_title : '',
            ], $this->get_current_actor_context()));
        }
        wp_safe_redirect( wp_get_referer() ?: home_url('/') ); exit;
    }
    public function handle_restore(){
        $this->check_nonce();
        $id=intval($_POST['post_id']??0);
        if($id){
            $post = get_post($id);
            $client = get_post_meta($id,'client_name',true);
            $site = get_post_meta($id,'site_url',true);
            $cn = get_post_meta($id,'cert_cn',true);
            wp_untrash_post($id);
            $this->log_activity('רשומת SSL שוחזרה', array_merge([
                'id' => $id,
                'client_name' => $client,
                'site_url' => $site,
                'common_name' => $cn,
                'post_title' => $post ? $post->post_title : '',
            ], $this->get_current_actor_context()));
        }
        wp_safe_redirect( wp_get_referer() ?: home_url('/') ); exit;
    }

    public function handle_export() {
        $filename='ssl-export-'.date('Ymd-His').'.csv';
        header('Content-Type: text/csv; charset=utf-8');
        header('Content-Disposition: attachment; filename='.$filename);
        $out=fopen('php://output','w');
        fputcsv($out,['client_name','site_url','expiry_date','common_name','source','notes','agent_only']);
        global $wpdb;
        $table = $this->get_table_name();
        $rows = $wpdb->get_results("SELECT * FROM {$table} WHERE status != 'trash'", ARRAY_A);
        $exported = 0;
        foreach($rows as $row){
            $client = $row['client_name'] ?? '';
            $site = $row['site_url'] ?? '';
            $expiry = !empty($row['expiry_ts']) ? gmdate('Y-m-d', (int)$row['expiry_ts']) : '';
            $cn = $row['common_name'] ?? '';
            $source = $row['source'] ?? '';
            $notes = $row['notes'] ?? '';
            $agent_only = !empty($row['agent_only']) ? 1 : 0;
            fputcsv($out, [$client, $site, $expiry, $cn, $source, $notes, $agent_only]);
            $exported++;
        }
        fclose($out);
        $this->log_activity('בוצע ייצוא רשומות', array_merge([
            'filename' => $filename,
            'exported' => $exported,
        ], $this->get_current_actor_context()));
        exit;
    }

    public function handle_import() {
        $this->check_nonce();
        $step = sanitize_text_field($_POST['ssl_import_step'] ?? '');
        if($step === 'preview'){
            if(empty($_FILES['import_file']) || $_FILES['import_file']['error'] !== UPLOAD_ERR_OK){
                wp_die('קובץ ייבוא לא התקבל');
            }
            $uploaded_name = sanitize_file_name($_FILES['import_file']['name'] ?? '');
            $rows = $this->parse_import_file($_FILES['import_file']['tmp_name'], $uploaded_name);
            if(is_wp_error($rows)){
                wp_die($rows->get_error_message());
            }
            $total = is_array($rows) ? count($rows) : 0;
            $key = substr(md5(uniqid('', true)), 0, 12);
            set_transient('ssl_import_'.$key, [
                'rows' => $rows,
                'filename' => $uploaded_name,
                'total' => $total,
                'created_at' => time(),
            ], HOUR_IN_SECONDS);
            $redirect = add_query_arg('ssl_preview', $key, wp_get_referer() ?: home_url('/'));
            wp_safe_redirect($redirect);
            exit;
        }

        if($step === 'confirm'){
            $preview_key = sanitize_key($_POST['preview_key'] ?? '');
            if(!$preview_key){
                wp_die('תצוגה מקדימה חסרה');
            }
            $preview_data = get_transient('ssl_import_'.$preview_key);
            if(empty($preview_data) || empty($preview_data['rows']) || !is_array($preview_data['rows'])){
                wp_die('הקובץ לתצוגה מקדימה אינו זמין');
            }
            $rows = $preview_data['rows'];
            $created = 0;
            $rows_logged = [];
            $rows_extra = 0;
            foreach($rows as $row){
                $client = sanitize_text_field($row['client_name'] ?? '');
                $site = $this->sanitize_url($row['site_url'] ?? '');
                $expiry_ts = !empty($row['expiry_ts']) ? (int)$row['expiry_ts'] : null;
                $source = isset($row['source']) ? $this->normalize_source_value($row['source'], 'manual') : 'manual';
                $notes = sanitize_textarea_field($row['notes'] ?? '');
                $agent_only = !empty($row['agent_only']) ? 1 : 0;
                $common_name = sanitize_text_field($row['common_name'] ?? '');
                if($client === '' && $site === ''){
                    continue;
                }
                $post_title = $client ?: ($site ?: 'SSL Item');
                $pid = wp_insert_post([
                    'post_type' => self::CPT,
                    'post_status' => 'publish',
                    'post_title' => $post_title,
                ]);
                if(is_wp_error($pid)){
                    continue;
                }
                update_post_meta($pid,'client_name',$client);
                update_post_meta($pid,'site_url',$site);
                if($expiry_ts){
                    update_post_meta($pid,'expiry_ts',$expiry_ts);
                }
                update_post_meta($pid,'source',$source);
                update_post_meta($pid,'notes',$notes);
                update_post_meta($pid,'agent_only',$agent_only);
                update_post_meta($pid,'cert_cn',$common_name);
                $this->sync_table_record($pid, get_post_status($pid));
                $created++;
                if(count($rows_logged) < 10){
                    $rows_logged[] = [
                        'id' => $pid,
                        'client_name' => $client,
                        'site_url' => $site,
                        'common_name' => $common_name,
                    ];
                } else {
                    $rows_extra++;
                }
            }
            delete_transient('ssl_import_'.$preview_key);
            $this->log_activity('בוצע ייבוא רשומות', array_merge([
                'filename' => $preview_data['filename'] ?? '',
                'created' => $created,
                'records' => $rows_logged,
                'records_additional' => $rows_extra,
            ], $this->get_current_actor_context()));
            $redirect = remove_query_arg('ssl_preview', wp_get_referer() ?: home_url('/'));
            wp_safe_redirect($redirect);
            exit;
        }

        wp_die('שלב ייבוא לא תקין');
    }

    public function ensure_cron(){ if(!wp_next_scheduled(self::CRON_HOOK)) wp_schedule_event(time()+300,'daily',self::CRON_HOOK); }
    public function cron_check_all() {
        $settings = $this->get_remote_client_settings();
        $remote_ready = $this->remote_client_is_ready($settings);
        $meta_query = [];
        if(!$remote_ready && !empty($settings['local_fallback'])){
            $meta_query[] = ['key'=>'agent_only','compare'=>'!=','value'=>1];
        }
        $args = [
            'post_type'=>self::CPT,
            'post_status'=>['publish','draft','pending'],
            'posts_per_page'=>-1,
        ];
        if(!empty($meta_query)){
            $args['meta_query'] = $meta_query;
        }
        $q=new WP_Query($args);
        if($q->have_posts()){
            while($q->have_posts()){ $q->the_post();
                $id=get_the_ID();
                $url=get_post_meta($id,'site_url',true);
                if(!$url) continue;
                if($remote_ready && $this->dispatch_remote_check($id,$url,'cron',$settings)){
                    continue;
                }
                if(!empty($settings['local_fallback'])){
                    $cert_details = $this->fetch_ssl_certificate_details($url);
                    if($cert_details){
                        $resolved_expiry = !empty($cert_details['expiry_ts']) ? (int)$cert_details['expiry_ts'] : 0;
                        $resolved_cn = !empty($cert_details['common_name']) ? sanitize_text_field($cert_details['common_name']) : '';
                        if($resolved_expiry){
                            update_post_meta($id,'expiry_ts',$resolved_expiry);
                        }
                        if($resolved_cn !== ''){
                            update_post_meta($id,'cert_cn',$resolved_cn);
                        }
                        update_post_meta($id,'source',$this->normalize_source_value('auto'));
                        delete_post_meta($id,'last_error');
                        $this->sync_table_record($id, get_post_status($id));
                        $this->log_activity('בדיקת SSL מקומית עודכנה', array_merge([
                            'id' => $id,
                            'client_name' => get_post_meta($id,'client_name',true),
                            'site_url' => $url,
                            'expiry_ts' => $resolved_expiry,
                            'common_name' => $resolved_cn,
                            'context' => 'cron',
                        ], $this->get_current_actor_context()));
                    }
                }
            }
            wp_reset_postdata();
        }
    }
    private function fetch_ssl_certificate_details($url){
        $parsed_url = wp_parse_url($url);
        if(!$parsed_url || empty($parsed_url['host'])){
            return null;
        }
        $host = $parsed_url['host'];
        $port = isset($parsed_url['port']) ? (int)$parsed_url['port'] : 443;
        $context = stream_context_create([
            'ssl' => [
                'capture_peer_cert' => true,
                'verify_peer' => false,
                'verify_peer_name' => false,
                'SNI_enabled' => true,
                'peer_name' => $host,
            ],
        ]);
        $client = @stream_socket_client("ssl://{$host}:{$port}", $errno, $errstr, 10, STREAM_CLIENT_CONNECT, $context);
        if(!$client){
            return null;
        }
        $params = stream_context_get_params($client);
        fclose($client);
        if(empty($params['options']['ssl']['peer_certificate'])){
            return null;
        }
        $certificate = $params['options']['ssl']['peer_certificate'];
        $cert_data = openssl_x509_parse($certificate);
        if(!$cert_data || empty($cert_data['validTo_time_t'])){
            return null;
        }
        $common_name = '';
        if(!empty($cert_data['subject']) && is_array($cert_data['subject'])){
            if(!empty($cert_data['subject']['CN'])){
                $common_name = $cert_data['subject']['CN'];
            } elseif(!empty($cert_data['subject']['commonName'])){
                $common_name = $cert_data['subject']['commonName'];
            }
        }
        if($common_name === '' && !empty($cert_data['extensions']['subjectAltName'])){
            $alt_names = explode(',', $cert_data['extensions']['subjectAltName']);
            foreach($alt_names as $alt){
                $alt = trim($alt);
                if(stripos($alt, 'DNS:') === 0){
                    $candidate = trim(substr($alt, 4));
                    if($candidate !== ''){
                        $common_name = $candidate;
                        break;
                    }
                }
            }
        }
        return [
            'expiry_ts' => (int)$cert_data['validTo_time_t'],
            'common_name' => $common_name,
        ];
    }

    private function collect_rest_tasks($limit, $force = false, $agent_filter = null){
        $limit = min(100, max(1, (int)$limit));
        $now = time();
        $stale = $now - DAY_IN_SECONDS;

        $meta_query = [
            'relation' => 'AND',
            [
                'key' => 'site_url',
                'value' => '',
                'compare' => '!=',
            ],
        ];

        if(!$force){
            $meta_query[] = [
                'relation' => 'OR',
                [
                    'key' => 'expiry_ts_checked_at',
                    'value' => $stale,
                    'compare' => '<=',
                    'type' => 'NUMERIC',
                ],
                [
                    'key' => 'expiry_ts_checked_at',
                    'compare' => 'NOT EXISTS',
                ],
            ];
        }

        if($agent_filter === true){
            $meta_query[] = [
                'key' => 'agent_only',
                'value' => 1,
                'compare' => '=',
                'type' => 'NUMERIC',
            ];
        } elseif($agent_filter === false){
            $meta_query[] = [
                'relation' => 'OR',
                [
                    'key' => 'agent_only',
                    'value' => 0,
                    'compare' => '=',
                    'type' => 'NUMERIC',
                ],
                [
                    'key' => 'agent_only',
                    'compare' => 'NOT EXISTS',
                ],
            ];
        }

        $query_args = [
            'post_type'      => self::CPT,
            'post_status'    => ['publish','draft','pending'],
            'posts_per_page' => $limit,
            'orderby'        => 'modified',
            'order'          => 'DESC',
            'meta_query'     => $meta_query,
        ];

        $q = new WP_Query($query_args);
        $tasks = [];

        if($q->have_posts()){
            while($q->have_posts()){ $q->the_post();
                $id = get_the_ID();
                $url = (string)get_post_meta($id,'site_url',true);
                if(!$url){
                    continue;
                }
                $tasks[] = [
                    'id' => $id,
                    'client_name' => (string)get_post_meta($id,'client_name',true),
                    'site_url' => $url,
                ];
                update_post_meta($id,'expiry_ts_checked_at', $now);
                $this->sync_table_record($id, get_post_status($id));
            }
        }
        wp_reset_postdata();

        return $tasks;
    }

    public function register_rest() {
        register_rest_route('ssl/v1','/tasks',['methods'=>'GET','permission_callback'=>'__return_true','callback'=>[$this,'rest_tasks']]);
        register_rest_route('ssl/v1','/report',['methods'=>'POST','permission_callback'=>'__return_true','callback'=>[$this,'rest_report']]);
        register_rest_route('ssl-agent/v1','/poll',[
            'methods'  => ['GET','POST'],
            'permission_callback' => '__return_true',
            'callback' => [$this,'rest_agent_poll'],
        ]);
        register_rest_route('ssl-agent/v1','/report',[
            'methods'  => ['POST'],
            'permission_callback' => '__return_true',
            'callback' => [$this,'rest_report'],
        ]);
    }
    private function rest_auth($req){
        $token=$req->get_header('x-agent-token') ?: '';
        if(!$token){
            $this->log_activity('בקשת Agent ללא טוקן', $this->get_current_actor_context(), 'warning');
            return new WP_Error('forbidden','invalid token',['status'=>403]);
        }
        $tokens=$this->ensure_default_token();
        foreach($tokens as $stored){
            if(!empty($stored['token']) && hash_equals($stored['token'], $token)){
                $previous_status = isset($stored['last_status']) ? (string)$stored['last_status'] : 'unknown';
                $updated = $this->mark_token_online($stored['id']);
                if($previous_status !== 'online'){
                    $this->log_activity('סוכן אומת בהצלחה', array_merge([
                        'token' => $stored['name'] ?? $stored['id'],
                    ], $this->get_current_actor_context()));
                }
                return ['token' => $updated ?: $stored];
            }
        }
        $fragment = substr($token, 0, 8);
        $this->log_activity('ניסיון אימות טוקן נכשל', array_merge([
            'token_fragment' => $fragment,
        ], $this->get_current_actor_context()), 'warning');
        return new WP_Error('forbidden','invalid token',['status'=>403]);
    }
    public function rest_tasks(WP_REST_Request $req){
        $auth=$this->rest_auth($req); if(is_wp_error($auth)) return $auth;
        $limit=min(100,max(1,intval($req->get_param('limit') ?: 50)));
        $agent_param=$req->get_param('agent_only');
        if($agent_param===null){
            $agent_filter=null;
        } else {
            $agent_filter = intval($agent_param) === 1 ? true : (intval($agent_param) === 0 ? false : null);
        }
        $items=$this->peek_queue_tasks($limit,$agent_filter);
        return new WP_REST_Response(['tasks'=>$items,'count'=>count($items),'pending'=>count($this->get_task_queue())],200);
    }

    public function rest_agent_poll(WP_REST_Request $req){
        $auth=$this->rest_auth($req); if(is_wp_error($auth)) return $auth;
        $limit=min(100,max(1,intval($req->get_param('limit') ?: 50)));
        $force=intval($req->get_param('force') ?: 0)===1;
        $agent_param=$req->get_param('agent_only');
        if($agent_param===null){
            $agent_filter=true;
        } else {
            $agent_filter = intval($agent_param) === 1 ? true : (intval($agent_param) === 0 ? false : null);
        }
        $token_data = is_array($auth) && isset($auth['token']) && is_array($auth['token']) ? $auth['token'] : [];
        $token_label = '';
        if(!empty($token_data['name'])){
            $token_label = (string)$token_data['name'];
        } elseif(!empty($token_data['id'])){
            $token_label = (string)$token_data['id'];
        }
        $items=$this->claim_queue_tasks($limit,$agent_filter,$token_label);
        if($force){
            $this->log_activity('סוכן דרש משימות בכפייה', array_merge([
                'limit' => $limit,
                'token' => $token_label,
            ], $this->get_current_actor_context()));
        }
        $queue = $this->get_task_queue();
        return new WP_REST_Response([
            'tasks'=>$items,
            'count'=>count($items),
            'pending'=>count($queue),
        ],200);
    }
    public function rest_report(WP_REST_Request $req){
        $auth=$this->rest_auth($req); if(is_wp_error($auth)) return $auth;
        $data=$req->get_json_params();
        $rows=is_array($data['results']??null)?$data['results']:[];
        $token_data = is_array($auth) && isset($auth['token']) && is_array($auth['token']) ? $auth['token'] : [];
        $token_label = '';
        if(!empty($token_data['name'])){
            $token_label = (string)$token_data['name'];
        } elseif(!empty($token_data['id'])){
            $token_label = (string)$token_data['id'];
        }
        foreach($rows as $row){
            $id=intval($row['id']??0); if(!$id) continue;
            $request_id = isset($row['request_id']) ? sanitize_text_field($row['request_id']) : '';
            $error_message = '';
            $expiry_ts = !empty($row['expiry_ts']) ? intval($row['expiry_ts']) : 0;
            $reported_source = $this->normalize_source_value($row['source'] ?? 'agent', 'agent');
            if($expiry_ts){
                update_post_meta($id,'expiry_ts',$expiry_ts);
                if($reported_source !== ''){
                    update_post_meta($id,'source',$reported_source);
                }
                delete_post_meta($id,'last_error');
            }
            $reported_cn = '';
            if(!empty($row['common_name'])){
                $reported_cn = sanitize_text_field($row['common_name']);
            } elseif(!empty($row['cn'])){
                $reported_cn = sanitize_text_field($row['cn']);
            }
            if($reported_cn !== ''){
                update_post_meta($id,'cert_cn',$reported_cn);
            }
            if(!empty($row['error'])){ $error_message = sanitize_text_field($row['error']); update_post_meta($id,'last_error',$error_message); }
            update_post_meta($id,'expiry_ts_checked_at', time());
            $this->sync_table_record($id, get_post_status($id));
            $check_label = !empty($row['check_name']) ? sanitize_text_field($row['check_name']) : '';
            $status_label = !empty($row['status']) ? sanitize_text_field($row['status']) : '';
            $latency_ms = isset($row['latency_ms']) ? intval($row['latency_ms']) : 0;
            $extra = [
                'token' => $token_label,
            ];
            if($check_label !== ''){
                $extra['agent_check'] = $check_label;
            }
            if($status_label !== ''){
                $extra['agent_status'] = $status_label;
            }
            if($latency_ms > 0){
                $extra['latency_ms'] = $latency_ms;
            }
            if($expiry_ts){
                $extra['expiry_ts'] = $expiry_ts;
            }
            if($reported_cn !== ''){
                $extra['common_name'] = $reported_cn;
            }
            if($reported_source !== ''){
                $extra['source'] = $reported_source;
            }
            if(!empty($row['executed_at'])){
                $extra['agent_executed_at'] = sanitize_text_field($row['executed_at']);
            }
            if(!empty($row['initiator'])){
                $extra['initiator'] = sanitize_text_field($row['initiator']);
            }
            if($error_message){
                $extra['error'] = $error_message;
                $this->complete_queue_task($id,$request_id,false,$error_message,$extra);
            } else {
                $this->complete_queue_task($id,$request_id,true,'',$extra);
            }
        }
        if(empty($rows)){
            $this->log_activity('דוח סוכן התקבל ללא תוצאות', array_merge([
                'token' => $token_label,
            ], $this->get_current_actor_context()));
        }
        return new WP_REST_Response(['ok'=>true,'updated'=>count($rows)],200);
    }

    public function settings_page(){
        add_options_page('SSL Expiry API','SSL Expiry API','manage_options','ssl-expiry-api',function(){
            if(!current_user_can('manage_options')){
                return;
            }
            $tokens = $this->ensure_default_token();
            $remote = $this->get_remote_client_settings();
            $remote_ready = $this->remote_client_is_ready($remote);
            echo '<div class="wrap"><h1>SSL Expiry API</h1>';
            if(!empty($_GET['remote-updated'])){
                echo '<div class="notice notice-success"><p>ההגדרות נשמרו בהצלחה.</p></div>';
            }
            echo '<p>ניהול הטוקנים מתבצע דרך הקיצור <code>[ssl_token_page]</code> בפרונט. להלן הטוקנים הפעילים:</p>';
            echo '<table class="widefat striped"><thead><tr><th>שם הטוקן</th><th>ערך</th><th>עודכן</th></tr></thead><tbody>';
            foreach($tokens as $token){
                $updated = !empty($token['updated']) ? date_i18n('Y-m-d H:i', (int)$token['updated']) : '';
                echo '<tr><td>'.esc_html($token['name']).'</td><td><code>'.esc_html($token['token']).'</code></td><td>'.esc_html($updated).'</td></tr>';
            }
            echo '</tbody></table>';
            $poll_url = rest_url('ssl-agent/v1/poll');
            $report_url = rest_url('ssl-agent/v1/report');
            echo '<p>כל קריאת REST חייבת לכלול Header בשם <code>X-Agent-Token</code>. נקודות הקצה הזמינות:</p>';
            echo '<ul style="list-style:disc;padding-right:20px;">';
            echo '<li><code>'.esc_html($poll_url).'</code> &mdash; משיכת משימות לסוכן.</li>';
            echo '<li><code>'.esc_html($report_url).'</code> &mdash; שליחת דוחות ביצוע.</li>';
            echo '</ul>';
            echo '<hr />';
            echo '<h2>הגדרות סוכן מרוחק</h2>';
            if($remote_ready){
                echo '<p><span style="color:#0a7a0a;font-weight:600;">הסוכן המרוחק פעיל.</span> משימות חדשות ייכנסו לתור ויאספו באמצעות השירות במשרד.</p>';
            } else {
                echo '<p><span style="color:#b91c1c;font-weight:600;">הסוכן המרוחק כבוי או לא זמין.</span> בהתאם להגדרות תתבצע בדיקה מקומית.</p>';
            }
            echo '<form method="post" action="'.esc_url(admin_url('admin-post.php')).'" class="ssl-remote-form">';
            wp_nonce_field('ssl_remote_client');
            echo '<input type="hidden" name="action" value="ssl_save_remote_client" />';
            echo '<table class="form-table" role="presentation"><tbody>';
            echo '<tr><th scope="row">הפעלת הסוכן</th><td><label><input type="checkbox" name="remote_enabled" value="1" '.checked(!empty($remote['enabled']),true,false).' /> אפשר לסוכן למשוך משימות מהתור</label></td></tr>';
            echo '<tr><th scope="row">Fallback מקומי</th><td><label><input type="checkbox" name="remote_local_fallback" value="1" '.checked(!empty($remote['local_fallback']),true,false).' /> בצע בדיקות ישירות כאשר הסוכן אינו פעיל</label></td></tr>';
            echo '<tr><th scope="row">REST Poll</th><td><code>'.esc_html($poll_url).'</code><p class="description">השתמש בקישור זה להגדרת שירות ה-Agent (GET/POST).</p></td></tr>';
            echo '<tr><th scope="row">REST Report</th><td><code>'.esc_html($report_url).'</code><p class="description">הסוכן שולח לכאן תוצאות באמצעות POST.</p></td></tr>';
            $primary_token_value = $this->get_primary_token_value();
            if($primary_token_value){
                echo '<tr><th scope="row">Token לאימות</th><td><code>'.esc_html($primary_token_value).'</code><p class="description">העבר ערך זה בכותרת <code>X-Agent-Token</code> בכל קריאה מהסוכן.</p></td></tr>';
            }
            echo '</tbody></table>';
            echo '<p class="submit"><button type="submit" class="button button-primary">שמירת הגדרות</button></p>';
            echo '</form>';
            echo '<p class="description">להתקנה מהירה ניתן להריץ את הפקודה <code>python3 remote_client_installer.py --wp-url='.esc_html(home_url('/')).' --agent-token=TOKEN</code> על התחנה במשרד. הסקריפט יוודא תלותים, יתקין את השירות ויתחבר לנקודות הקצה לעיל.</p>';

            $queue = $this->get_task_queue();
            echo '<hr /><h2>תור משימות</h2>';
            if(empty($queue)){
                echo '<p>אין משימות ממתינות בתור.</p>';
            } else {
                echo '<p>כמות משימות ממתינות: <strong>'.count($queue).'</strong>.</p>';
                echo '<table class="widefat striped"><thead><tr><th>ID</th><th>לקוח</th><th>URL</th><th>הקשר</th><th>סטטוס</th><th>זמן</th></tr></thead><tbody>';
                foreach($queue as $job){
                    $status = $job['status'] === 'claimed' ? 'בתהליך' : 'ממתין';
                    $time = !empty($job['claimed_at']) ? (int)$job['claimed_at'] : (int)$job['enqueued_at'];
                    $time_label = $time ? date_i18n('Y-m-d H:i', $time) : '';
                    echo '<tr>';
                    echo '<td>'.esc_html($job['id']).'</td>';
                    echo '<td>'.esc_html($job['client_name']).'</td>';
                    echo '<td><code>'.esc_html($job['site_url']).'</code></td>';
                    echo '<td>'.esc_html($job['context']).'</td>';
                    echo '<td>'.esc_html($status).'</td>';
                    echo '<td>'.esc_html($time_label).'</td>';
                    echo '</tr>';
                }
                echo '</tbody></table>';
            }

            $log_entries = array_reverse($this->get_activity_log());
            $log_limit = array_slice($log_entries, 0, 50);
            echo '<hr /><h2>לוג פעילות</h2>';
            if(empty($log_limit)){
                echo '<p>לא קיימות רשומות פעילות בשלב זה.</p>';
            } else {
                echo '<p>מוצגות עד 50 הרשומות האחרונות (החדשה ביותר בראש).</p>';
                echo '<table class="widefat striped"><thead><tr><th>זמן</th><th>רמה</th><th>תיאור</th><th>פרטים</th></tr></thead><tbody>';
                foreach($log_limit as $entry){
                    $time = !empty($entry['time']) ? date_i18n('Y-m-d H:i:s', (int)$entry['time']) : '';
                    $level = strtoupper(esc_html($entry['level'] ?? 'info'));
                    $message = esc_html($entry['message'] ?? '');
                    $context = '';
                    if(!empty($entry['context'])){
                        $context_json = wp_json_encode($entry['context'], JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
                        if($context_json){
                            $context = '<code>'.esc_html($context_json).'</code>';
                        }
                    }
                    echo '<tr>';
                    echo '<td>'.esc_html($time).'</td>';
                    echo '<td>'.esc_html($level).'</td>';
                    echo '<td>'.$message.'</td>';
                    echo '<td>'.$context.'</td>';
                    echo '</tr>';
                }
                echo '</tbody></table>';
            }
            echo '</div>';
        });
    }
    public function on_activate(){
        if(!get_option(self::OPTION_TOKEN)) add_option(self::OPTION_TOKEN, wp_generate_password(32,false,false));
        if(!get_page_by_path('ssl-trash')){
            wp_insert_post(['post_title'=>'סל מחזור SSL','post_name'=>'ssl-trash','post_type'=>'page','post_status'=>'publish','post_content'=>'[ssl_trash]']);
        }
        $this->ensure_sql_table();
        $this->maybe_seed_sql_table();
    }
    public function route_export_helper(){
        if(!empty($_GET['ssl_action']) && $_GET['ssl_action']==self::EXPORT_ACTION){
            do_action('admin_post_nopriv_'.self::EXPORT_ACTION); exit;
        }
    }
}
}

if (!isset($GLOBALS['ssl_expiry_manager_aio']) || !($GLOBALS['ssl_expiry_manager_aio'] instanceof SSL_Expiry_Manager_AIO)) {
    $GLOBALS['ssl_expiry_manager_aio'] = new SSL_Expiry_Manager_AIO();
}
