<?php
/**
 * Plugin Name: SSL Expiry Manager
 * Description: ניהול ובדיקת תוקף תעודות SSL בטבלה עם עריכה, ייבוא/ייצוא CSV וסל מחזור (90 יום).
 * Version: 1.0.0
 * Author: Ofri + GPT
 */

if (!defined('ABSPATH')) exit;

class SSL_Expiry_Manager {
    const CPT = 'ssl_cert';
    const CRON_HOOK = 'ssl_expiry_manager_daily_check';
    const NONCE = 'ssl_expiry_manager_nonce';
    const EXPORT_ACTION = 'ssl_expiry_export';
    const IMPORT_ACTION = 'ssl_expiry_import';
    const SAVE_ACTION   = 'ssl_expiry_save';
    const DELETE_ACTION = 'ssl_expiry_delete';
    const RESTORE_ACTION= 'ssl_expiry_restore';

    public function __construct() {
        // Register CPT and fields
        add_action('init', [$this,'register_cpt']);
        add_action('init', [$this,'register_meta']);

        // Shortcodes
        add_shortcode('ssl_cert_table', [$this,'shortcode_table']);
        add_shortcode('ssl_trash',      [$this,'shortcode_trash']);

        // Assets
        add_action('wp_enqueue_scripts', [$this,'assets']);

        // Form handlers (front-end, פתוח לכולם)
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

        // Cron
        add_action('wp', [$this,'ensure_cron']);
        add_action(self::CRON_HOOK, [$this,'cron_check_all']);

        // Trash retention 90 days
        add_filter('empty_trash_days', function(){ return 90; });

        // Allow multi image upload via front-end
        add_action('init', function(){ if(!function_exists('wp_handle_upload')) require_once(ABSPATH.'wp-admin/includes/file.php'); });
    }

    /* =========================
       Data model
       ========================= */
    public function register_cpt() {
        register_post_type(self::CPT, [
            'label' => 'SSL Certificates',
            'public' => false,
            'show_ui' => true,
            'supports' => ['title'],
            'capability_type' => 'post',
            'map_meta_cap' => true,
            'has_archive' => false,
            'show_in_rest' => false,
        ]);
    }

    public function register_meta() {
        $fields = [
            'client_name' => 'string',
            'site_url'    => 'string',
            'expiry_ts'   => 'integer', // Unix time
            'source'      => 'string',  // manual | auto
            'notes'       => 'string',
            'images'      => 'array',   // attachment IDs
        ];
        foreach ($fields as $key=>$type) {
            register_post_meta(self::CPT, $key, [
                'type' => $type==='array' ? 'array' : $type,
                'single' => true,
                'show_in_rest' => false,
                'auth_callback' => '__return_true',
            ]);
        }
    }

    /* =========================
       Assets
       ========================= */
    public function assets() {
        // Minimal styles + inline JS for toggle edit
        $css = "
        .ssl-table { width:100%; border-collapse:collapse; }
        .ssl-table th, .ssl-table td { border:1px solid #ddd; padding:8px; text-align:right; }
        .ssl-badge { padding:2px 8px; border-radius:12px; color:#000; display:inline-block; min-width:70px; text-align:center; font-weight:600;}
        .ssl-green{ background:#c6f6d5;}
        .ssl-yellow{ background:#fefcbf;}
        .ssl-red{ background:#fed7d7;}
        .ssl-actions { display:flex; gap:6px; flex-wrap:wrap; justify-content:flex-end;}
        .ssl-form { border:1px solid #ddd; padding:12px; margin:12px 0; background:#fafafa; }
        .ssl-form input[type=text], .ssl-form input[type=url], .ssl-form textarea { width:100%; padding:8px; }
        .ssl-form label { display:block; margin-top:8px; }
        .ssl-toolbar{ display:flex; gap:10px; align-items:center; justify-content:space-between; margin:10px 0;}
        .ssl-note{ font-size:12px; color:#666;}
        .ssl-btn{ display:inline-block; padding:6px 12px; border:1px solid #999; background:#fff; cursor:pointer; text-decoration:none;}
        .ssl-btn:hover{ background:#f0f0f0;}
        ";
        wp_register_style('ssl-expiry-manager', false);
        wp_enqueue_style('ssl-expiry-manager');
        wp_add_inline_style('ssl-expiry-manager', $css);

        $js = "
        document.addEventListener('click',function(e){
          var t=e.target;
          if(t.matches('[data-ssl-edit]')){
            var id=t.getAttribute('data-ssl-edit');
            var row=document.querySelector('[data-ssl-form=\"'+id+'\"]');
            if(row){ row.hidden = !row.hidden; }
          }
        });
        ";
        wp_register_script('ssl-expiry-manager-js', '', [], false, true);
        wp_enqueue_script('ssl-expiry-manager-js');
        wp_add_inline_script('ssl-expiry-manager-js',$js);
    }

    /* =========================
       Helpers
       ========================= */
    private function nonce_field() {
        return wp_nonce_field(self::NONCE, self::NONCE, true, false);
    }
    private function check_nonce() {
        if (!isset($_POST[self::NONCE]) || !wp_verify_nonce($_POST[self::NONCE], self::NONCE)) {
            wp_die('Invalid nonce');
        }
    }
    private function sanitize_url($url) {
        $url = trim($url);
        if ($url && !preg_match('#^https?://#i',$url)) $url = 'https://'.$url;
        return esc_url_raw($url);
    }
    private function days_left($expiry_ts) {
        if (!$expiry_ts) return null;
        $now = current_time('timestamp');
        return (int) floor(($expiry_ts - $now) / DAY_IN_SECONDS);
    }
    private function badge_class($days){
        if ($days === null) return '';
        if ($days > 90) return 'ssl-green';
        if ($days > 30) return 'ssl-yellow';
        return 'ssl-red';
    }
    private function fmt_date($ts){
        return $ts ? date_i18n('Y-m-d', $ts) : '';
    }
    private function output_url_button($url){
        if(!$url) return '';
        $u = esc_url($url);
        return "<a class='ssl-btn' target='_blank' rel='noopener' href='{$u}'>פתיחת אתר</a>";
    }

    /* =========================
       Shortcode: Main table
       ========================= */
    public function shortcode_table($atts) {
        // Handle create new button toggle
        $create_hidden = empty($_GET['ssl_new']) ? 'hidden' : '';

        ob_start();

        // Toolbar
        echo "<div class='ssl-toolbar'>";
        echo "<div><a class='ssl-btn' href='".esc_url(add_query_arg('ssl_new','1'))."'>הוסף רשומה</a> ";
        echo "<a class='ssl-btn' href='".esc_url(site_url('?ssl_action='.self::EXPORT_ACTION))."'>ייצוא CSV</a></div>";
        // Import form
        echo "<form method='post' action='".esc_url(admin_url('admin-post.php'))."' enctype='multipart/form-data' style='display:flex; gap:8px; align-items:center;'>";
        echo $this->nonce_field();
        echo "<input type='hidden' name='action' value='".esc_attr(self::IMPORT_ACTION)."'/>";
        echo "<input type='file' name='csv' accept='.csv' required />";
        echo "<button class='ssl-btn' type='submit'>ייבוא CSV</button>";
        echo "</form>";
        echo "<div><a class='ssl-btn' href='".esc_url(add_query_arg([],
             get_permalink()))."'>רענון</a> <a class='ssl-btn' href='".esc_url(add_query_arg([],site_url('/?page=ssl-trash')))."'>סל מחזור</a></div>";
        echo "</div>";

        // Create form
        echo "<div class='ssl-form' {$create_hidden}>";
        echo "<form method='post' action='".esc_url(admin_url('admin-post.php'))."' enctype='multipart/form-data'>";
        echo $this->nonce_field();
        echo "<input type='hidden' name='action' value='".esc_attr(self::SAVE_ACTION)."' />";
        echo "<input type='hidden' name='post_id' value='0' />";
        echo "<label>שם הלקוח<input type='text' name='client_name' required></label>";
        echo "<label>אתר (URL)<input type='url' name='site_url' placeholder='https://example.com'></label>";
        echo "<label>תאריך תפוגה (YYYY-MM-DD) <input type='text' name='expiry_date' placeholder='2026-12-31'></label>";
        echo "<label>ליקוט
                <select name='source'>
                  <option value='manual'>ידני</option>
                  <option value='auto'>אוטומטי</option>
                </select>
              </label>";
        echo "<label>הערות<textarea name='notes' rows='3'></textarea></label>";
        echo "<label>תמונות<input type='file' name='images[]' multiple accept='image/*'></label>";
        echo "<button class='ssl-btn' type='submit'>שמור</button>";
        echo "</form>";
        echo "<div class='ssl-note'>הערה: בדיקה אוטומטית יומית תעדכן את תאריך התפוגה ע״פ ה-SSL בפועל.</div>";
        echo "</div>";

        // Query posts (not trashed)
        $q = new WP_Query([
            'post_type' => self::CPT,
            'post_status' => ['publish','draft','pending'],
            'posts_per_page' => -1,
            'orderby' => 'title',
            'order' => 'ASC',
        ]);

        echo "<table class='ssl-table'>";
        echo "<thead><tr>
                <th>שם הלקוח</th>
                <th>אתר</th>
                <th>פתיחה</th>
                <th>תאריך תפוגה</th>
                <th>ימים</th>
                <th>ליקוט</th>
                <th>הערות</th>
                <th>תמונות</th>
                <th>פעולות</th>
              </tr></thead><tbody>";

        if ($q->have_posts()){
            while($q->have_posts()){ $q->the_post();
                $id = get_the_ID();
                $client = get_post_meta($id,'client_name',true);
                $url    = get_post_meta($id,'site_url',true);
                $expiry = (int) get_post_meta($id,'expiry_ts',true);
                $src    = get_post_meta($id,'source',true);
                $notes  = get_post_meta($id,'notes',true);
                $imgs   = get_post_meta($id,'images',true);
                if (!is_array($imgs)) $imgs = [];

                $days = $this->days_left($expiry);
                $badge = $this->badge_class($days);
                $days_txt = ($days===null) ? '' : $days;

                echo "<tr>";
                echo "<td>".esc_html($client)."</td>";
                echo "<td><a target='_blank' rel='noopener' href='".esc_url($url)."'>".esc_html($url)."</a></td>";
                echo "<td>".$this->output_url_button($url)."</td>";
                echo "<td>".$this->fmt_date($expiry)."</td>";
                echo "<td><span class='ssl-badge {$badge}'>".$days_txt."</span></td>";
                echo "<td>".esc_html($src ? $src : '')."</td>";
                echo "<td>".nl2br(esc_html($notes))."</td>";
                echo "<td>";
                if ($imgs){
                    foreach($imgs as $aid){
                        $srcImg = wp_get_attachment_image_url($aid,'thumbnail');
                        if ($srcImg) echo "<a target='_blank' href='".esc_url(wp_get_attachment_url($aid))."'><img src='".esc_url($srcImg)."' style='max-width:60px; max-height:60px; margin:2px;'/></a>";
                    }
                }
                echo "</td>";
                echo "<td class='ssl-actions'>";
                echo "<a class='ssl-btn' href='javascript:void(0)' data-ssl-edit='".esc_attr($id)."'>עריכה</a>";
                // Soft delete -> trash
                $del_url = esc_url( add_query_arg([], admin_url('admin-post.php')) );
                echo "<form method='post' action='{$del_url}' style='display:inline'>";
                echo $this->nonce_field();
                echo "<input type='hidden' name='action' value='".esc_attr(self::DELETE_ACTION)."' />";
                echo "<input type='hidden' name='post_id' value='".esc_attr($id)."' />";
                echo "<button class='ssl-btn' type='submit' onclick='return confirm(\"להעביר לסל מחזור?\")'>מחיקה</button>";
                echo "</form>";
                echo "</td>";
                echo "</tr>";

                // Inline edit form
                echo "<tr data-ssl-form='".esc_attr($id)."' hidden><td colspan='9'>";
                echo "<div class='ssl-form'>";
                $save_url = esc_url( admin_url('admin-post.php') );
                echo "<form method='post' action='{$save_url}' enctype='multipart/form-data'>";
                echo $this->nonce_field();
                echo "<input type='hidden' name='action' value='".esc_attr(self::SAVE_ACTION)."' />";
                echo "<input type='hidden' name='post_id' value='".esc_attr($id)."' />";
                echo "<label>שם הלקוח<input type='text' name='client_name' value='".esc_attr($client)."'></label>";
                echo "<label>אתר (URL)<input type='url' name='site_url' value='".esc_attr($url)."'></label>";
                echo "<label>תאריך תפוגה (YYYY-MM-DD) <input type='text' name='expiry_date' value='".esc_attr($this->fmt_date($expiry))."'></label>";
                echo "<label>ליקוט
                        <select name='source'>
                          <option value='manual' ".selected($src,'manual',false).">ידני</option>
                          <option value='auto' ".selected($src,'auto',false).">אוטומטי</option>
                        </select>
                      </label>";
                echo "<label>הערות<textarea name='notes' rows='3'>".esc_textarea($notes)."</textarea></label>";
                echo "<label>תמונות (להוסיף חדשות) <input type='file' name='images[]' multiple accept='image/*'></label>";
                echo "<button class='ssl-btn' type='submit'>שמור</button>";
                echo "</form>";
                echo "</div>";
                echo "</td></tr>";
            }
            wp_reset_postdata();
        } else {
            echo "<tr><td colspan='9'>אין נתונים</td></tr>";
        }

        echo "</tbody></table>";
        echo "<div class='ssl-note'>צבעי האינדיקטור: ירוק &gt; 90 יום, צהוב 31–90, אדום ≤ 30.</div>";

        return ob_get_clean();
    }

    /* =========================
       Shortcode: Trash page
       ========================= */
    public function shortcode_trash($atts) {
        $q = new WP_Query([
            'post_type' => self::CPT,
            'post_status' => 'trash',
            'posts_per_page' => -1,
            'orderby' => 'modified',
            'order' => 'DESC',
        ]);
        ob_start();
        echo "<h3>סל מחזור</h3>";
        echo "<div><a class='ssl-btn' href='".esc_url(add_query_arg([],site_url('/')))."'>חזרה</a></div>";
        echo "<table class='ssl-table'><thead><tr><th>שם הלקוח</th><th>אתר</th><th>נמחק בתאריך</th><th>שחזור</th></tr></thead><tbody>";
        if ($q->have_posts()){
            while($q->have_posts()){ $q->the_post();
                $id = get_the_ID();
                $url= get_post_meta($id,'site_url',true);
                echo "<tr>";
                echo "<td>".esc_html(get_post_meta($id,'client_name',true))."</td>";
                echo "<td>".esc_html($url)."</td>";
                echo "<td>".esc_html(get_the_modified_date('Y-m-d'))."</td>";
                $restore_url = esc_url( admin_url('admin-post.php') );
                echo "<td><form method='post' action='{$restore_url}'>".$this->nonce_field()."
                        <input type='hidden' name='action' value='".esc_attr(self::RESTORE_ACTION)."' />
                        <input type='hidden' name='post_id' value='".esc_attr($id)."' />
                        <button class='ssl-btn' type='submit'>שחזר</button>
                      </form></td>";
                echo "</tr>";
            }
            wp_reset_postdata();
        } else {
            echo "<tr><td colspan='4'>הרשימות הריקות</td></tr>";
        }
        echo "</tbody></table>";
        echo "<div class='ssl-note'>רכיבים נמחקים נשמרים במשך 90 יום לפני ריקון אוטומטי.</div>";
        return ob_get_clean();
    }

    /* =========================
       Form handlers
       ========================= */
    public function handle_save() {
        $this->check_nonce();

        $post_id     = intval($_POST['post_id'] ?? 0);
        $client_name = sanitize_text_field($_POST['client_name'] ?? '');
        $site_url    = $this->sanitize_url($_POST['site_url'] ?? '');
        $expiry_date = sanitize_text_field($_POST['expiry_date'] ?? '');
        $source      = in_array($_POST['source'] ?? 'manual', ['manual','auto'], true) ? $_POST['source'] : 'manual';
        $notes       = sanitize_textarea_field($_POST['notes'] ?? '');

        // Parse expiry date to timestamp if provided
        $expiry_ts = null;
        if ($expiry_date) {
            $t = strtotime($expiry_date.' 00:00:00');
            if ($t) $expiry_ts = $t;
        }

        if ($post_id) {
            // Update
            wp_update_post(['ID'=>$post_id, 'post_title'=>$client_name ?: 'SSL Item']);
        } else {
            $post_id = wp_insert_post([
                'post_type' => self::CPT,
                'post_status' => 'publish',
                'post_title' => $client_name ?: 'SSL Item',
            ]);
        }

        if ($post_id && !is_wp_error($post_id)) {
            update_post_meta($post_id,'client_name',$client_name);
            update_post_meta($post_id,'site_url',$site_url);
            if ($expiry_ts) update_post_meta($post_id,'expiry_ts',$expiry_ts);
            update_post_meta($post_id,'source',$source);
            update_post_meta($post_id,'notes',$notes);

            // Handle images
            if (!empty($_FILES['images']) && is_array($_FILES['images']['name'])) {
                $ids = get_post_meta($post_id,'images',true);
                if (!is_array($ids)) $ids=[];
                $files = $_FILES['images'];
                for($i=0; $i<count($files['name']); $i++){
                    if ($files['error'][$i]===UPLOAD_ERR_OK && $files['size'][$i]>0){
                        $file_array = [
                            'name' => sanitize_file_name($files['name'][$i]),
                            'type' => $files['type'][$i],
                            'tmp_name' => $files['tmp_name'][$i],
                            'error' => 0,
                            'size' => $files['size'][$i],
                        ];
                        $overrides = ['test_form'=>false];
                        $movefile = wp_handle_upload($file_array, $overrides);
                        if ($movefile && !isset($movefile['error'])) {
                            $attachment = [
                                'post_mime_type'=>$movefile['type'],
                                'post_title'=> sanitize_file_name($file_array['name']),
                                'post_status'=>'inherit'
                            ];
                            $attach_id = wp_insert_attachment($attachment, $movefile['file'], $post_id);
                            require_once(ABSPATH.'wp-admin/includes/image.php');
                            $attach_data = wp_generate_attachment_metadata($attach_id, $movefile['file']);
                            wp_update_attachment_metadata($attach_id, $attach_data);
                            $ids[] = $attach_id;
                        }
                    }
                }
                update_post_meta($post_id,'images',$ids);
            }
        }

        wp_safe_redirect( wp_get_referer() ?: home_url('/') );
        exit;
    }

    public function handle_delete() {
        $this->check_nonce();
        $post_id = intval($_POST['post_id'] ?? 0);
        if ($post_id) wp_trash_post($post_id);
        wp_safe_redirect( wp_get_referer() ?: home_url('/') );
        exit;
    }

    public function handle_restore() {
        $this->check_nonce();
        $post_id = intval($_POST['post_id'] ?? 0);
        if ($post_id) wp_untrash_post($post_id);
        wp_safe_redirect( wp_get_referer() ?: home_url('/') );
        exit;
    }

    /* =========================
       CSV Export / Import
       ========================= */
    public function handle_export() {
        // No nonce to allow open export link; if נדרש, אפשר להוסיף.
        $filename = 'ssl-export-'.date('Ymd-His').'.csv';
        header('Content-Type: text/csv; charset=utf-8');
        header('Content-Disposition: attachment; filename='.$filename);
        $out = fopen('php://output','w');
        fputcsv($out, ['client_name','site_url','expiry_date','source','notes','image_urls']);
        $q = new WP_Query(['post_type'=>self::CPT,'post_status'=>['publish','draft','pending','trash'],'posts_per_page'=>-1]);
        if ($q->have_posts()){
            while($q->have_posts()){ $q->the_post();
                $id = get_the_ID();
                $client = get_post_meta($id,'client_name',true);
                $site   = get_post_meta($id,'site_url',true);
                $expiry = get_post_meta($id,'expiry_ts',true);
                $src    = get_post_meta($id,'source',true);
                $notes  = get_post_meta($id,'notes',true);
                $imgs   = get_post_meta($id,'images',true);
                $img_urls=[];
                if (is_array($imgs)) foreach($imgs as $aid){ $u=wp_get_attachment_url($aid); if($u) $img_urls[]=$u; }
                fputcsv($out, [
                    $client,
                    $site,
                    $expiry ? date('Y-m-d',$expiry) : '',
                    $src,
                    $notes,
                    implode('|',$img_urls)
                ]);
            }
            wp_reset_postdata();
        }
        fclose($out);
        exit;
    }

    public function handle_import() {
        $this->check_nonce();
        if (empty($_FILES['csv']) || $_FILES['csv']['error']!==UPLOAD_ERR_OK) {
            wp_die('קובץ CSV לא תקין');
        }
        $fh = fopen($_FILES['csv']['tmp_name'],'r');
        if (!$fh) wp_die('כשל בקריאת הקובץ');
        // Header
        $header = fgetcsv($fh);
        // Expected: client_name, site_url, expiry_date, source, notes, image_urls
        while(($row=fgetcsv($fh))!==false){
            $map = array_pad($row,6,'');
            list($client,$site,$exp,$src,$notes,$image_urls) = $map;

            $post_id = wp_insert_post([
                'post_type'=>self::CPT,
                'post_status'=>'publish',
                'post_title'=> $client ?: 'SSL Item',
            ]);
            if (is_wp_error($post_id)) continue;

            update_post_meta($post_id,'client_name',sanitize_text_field($client));
            update_post_meta($post_id,'site_url',$this->sanitize_url($site));
            $ts = $exp ? strtotime($exp.' 00:00:00') : null;
            if ($ts) update_post_meta($post_id,'expiry_ts',$ts);
            update_post_meta($post_id,'source', in_array($src,['manual','auto'],true)?$src:'manual');
            update_post_meta($post_id,'notes',sanitize_textarea_field($notes));

            $ids=[];
            if ($image_urls){
                $urls = explode('|',$image_urls);
                foreach($urls as $iu){
                    $iu = esc_url_raw(trim($iu));
                    // לא מוריד קבצים חיצוניים אוטומטית. דלג.
                    // אפשר לעתיד להרחיב ל-download_sideload.
                }
                if ($ids) update_post_meta($post_id,'images',$ids);
            }
        }
        fclose($fh);
        wp_safe_redirect( wp_get_referer() ?: home_url('/') );
        exit;
    }

    /* =========================
       Cron: Daily SSL check
       ========================= */
    public function ensure_cron() {
        if (!wp_next_scheduled(self::CRON_HOOK)) {
            wp_schedule_event(time()+300, 'daily', self::CRON_HOOK);
        }
    }

    public function cron_check_all() {
        $q = new WP_Query([
            'post_type'=>self::CPT,
            'post_status'=>['publish','draft','pending'],
            'posts_per_page'=>-1,
        ]);
        if ($q->have_posts()){
            while($q->have_posts()){ $q->the_post();
                $id   = get_the_ID();
                $url  = get_post_meta($id,'site_url',true);
                if (!$url) continue;
                $exp_ts = $this->fetch_ssl_expiry_ts($url);
                if ($exp_ts){
                    update_post_meta($id,'expiry_ts',$exp_ts);
                    update_post_meta($id,'source','auto');
                }
            }
            wp_reset_postdata();
        }
    }

    /**
     * Try to get SSL cert expiry unix time from a URL host:port.
     */
    private function fetch_ssl_expiry_ts($url){
        $parts = wp_parse_url($url);
        if (!$parts || empty($parts['host'])) return null;
        $host = $parts['host'];
        $port = isset($parts['port']) ? intval($parts['port']) : 443;

        $ctx = stream_context_create([
            'ssl'=>[
                'capture_peer_cert' => true,
                'verify_peer' => false,
                'verify_peer_name' => false,
                'SNI_enabled' => true,
                'peer_name' => $host,
            ]
        ]);
        $client = @stream_socket_client("ssl://{$host}:{$port}", $errno, $errstr, 10, STREAM_CLIENT_CONNECT, $ctx);
        if (!$client) return null;
        $params = stream_context_get_params($client);
        if (!isset($params['options']['ssl']['peer_certificate'])) return null;
        $cert = $params['options']['ssl']['peer_certificate'];
        $parsed = openssl_x509_parse($cert);
        if (!$parsed || empty($parsed['validTo_time_t'])) return null;
        return (int)$parsed['validTo_time_t'];
    }
}

new SSL_Expiry_Manager();

/* =========
   Simple route helper to map site/?ssl_action=ssl_expiry_export
   ========= */
add_action('init', function(){
    if (!empty($_GET['ssl_action']) && $_GET['ssl_action']==SSL_Expiry_Manager::EXPORT_ACTION){
        do_action('admin_post_nopriv_'.SSL_Expiry_Manager::EXPORT_ACTION);
        exit;
    }
});

/* =========
   Optional: יצירת עמוד “סל מחזור” אוטומטי בעת הפעלת התוסף
   ========= */
register_activation_hook(__FILE__, function(){
    if (!get_page_by_path('ssl-trash')) {
        wp_insert_post([
            'post_title'=>'סל מחזור SSL',
            'post_name'=>'ssl-trash',
            'post_type'=>'page',
            'post_status'=>'publish',
            'post_content'=>'[ssl_trash]'
        ]);
    }
});
