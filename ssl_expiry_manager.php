<?php
/**
 * Plugin Name: SSL Expiry Manager (All-in-One + Front Controls + Token Page)
 * Description: ניהול ובדיקת תוקף SSL בטבלה עם עריכה, ייבוא/ייצוא CSV, סל מחזור 90 יום, REST לסוכן מקומי, בקרות פרונט ועמוד ניהול טוקן.
 * Version: 1.5.0
 * Author: Ofri + GPT
 */
if (!defined('ABSPATH')) exit;

class SSL_Expiry_Manager_AIO {
    const CPT = 'ssl_cert';
    const CRON_HOOK = 'ssl_expiry_manager_daily_check';
    const NONCE = 'ssl_expiry_manager_nonce';
    const EXPORT_ACTION = 'ssl_expiry_export';
    const IMPORT_ACTION = 'ssl_expiry_import';
    const SAVE_ACTION   = 'ssl_expiry_save';
    const DELETE_ACTION = 'ssl_expiry_delete';
    const RESTORE_ACTION= 'ssl_expiry_restore';
    const OPTION_TOKEN  = 'ssl_em_api_token';

    public function __construct() {
        add_action('init', [$this,'register_cpt']);
        add_action('init', [$this,'register_meta']);
        add_shortcode('ssl_cert_table', [$this,'shortcode_table']);
        add_shortcode('ssl_trash',      [$this,'shortcode_trash']);
        add_shortcode('ssl_controls',   [$this,'shortcode_controls']);
        add_shortcode('ssl_token',      [$this,'shortcode_token']);
        add_shortcode('ssl_token_page', [$this,'shortcode_token_page']); // חדש
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

        add_action('wp', [$this,'ensure_cron']);
        add_action(self::CRON_HOOK, [$this,'cron_check_all']);

        add_filter('empty_trash_days', function(){ return 90; });
        add_action('init', function(){ if(!function_exists('wp_handle_upload')) require_once(ABSPATH.'wp-admin/includes/file.php'); });

        add_action('rest_api_init', [$this,'register_rest']);
        add_action('admin_menu',    [$this,'settings_page']);
        register_activation_hook(__FILE__, [$this,'on_activate']);
        add_action('init', [$this,'route_export_helper']);
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
        ];
        foreach ($fields as $k=>$t){
            register_post_meta(self::CPT,$k,[
                'type'=> $t==='array'?'array':$t,'single'=>true,'show_in_rest'=>false,'auth_callback'=>'__return_true',
            ]);
        }
    }

    public function assets() {
        $css = <<<'CSS'
.ssl-manager{direction:rtl;font-family:"Assistant","Rubik",Arial,sans-serif;background:#fff;border-radius:16px;box-shadow:0 12px 30px rgba(15,23,42,.08);padding:24px;margin:24px auto;max-width:1200px;display:flex;flex-direction:column;gap:24px;}
@media (max-width:768px){.ssl-manager{padding:18px;}}
.ssl-manager__header{display:flex;flex-wrap:wrap;justify-content:space-between;gap:16px;padding-bottom:16px;border-bottom:1px solid #e2e8f0;}
.ssl-manager__title h2{margin:0;color:#0f172a;font-size:1.75rem;font-weight:700;}
.ssl-manager__subtitle{color:#64748b;font-size:.95rem;margin-top:4px;}
.ssl-manager__header-actions{display:flex;gap:10px;align-items:center;}
.ssl-toolbar{display:grid;grid-template-columns:repeat(auto-fit,minmax(240px,1fr));gap:12px;}
.ssl-toolbar__group,.ssl-toolbar__import{display:flex;gap:10px;align-items:center;justify-content:flex-start;background:#f8fafc;border:1px solid #e2e8f0;border-radius:12px;padding:12px;}
.ssl-toolbar__group--end{justify-content:flex-end;}
.ssl-toolbar__import{justify-content:space-between;flex-wrap:wrap;}
.ssl-toolbar__import input[type=file]{flex:1 1 180px;font-size:.9rem;color:#475569;}
.ssl-btn{display:inline-flex;align-items:center;justify-content:center;gap:6px;padding:.55rem 1.3rem;border-radius:10px;border:1px solid transparent;font-weight:600;font-size:.95rem;cursor:pointer;text-decoration:none;transition:transform .15s ease,box-shadow .15s ease,background .15s ease,color .15s ease;}
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
.ssl-table tbody td{padding:14px 12px;border-bottom:1px solid #e2e8f0;vertical-align:middle;color:#1e293b;font-size:.95rem;}
.ssl-table tbody tr:nth-child(even){background:#f8fafc;}
.ssl-table tbody tr:hover{background:#eef2ff;}
.ssl-table tbody tr:last-child td{border-bottom:none;}
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
.ssl-card__footer--links{justify-content:flex-start;}
.ssl-card__footer{display:flex;gap:10px;align-items:center;flex-wrap:wrap;justify-content:flex-start;}
.ssl-card--form label{display:flex;flex-direction:column;gap:6px;color:#475569;font-weight:600;font-size:.9rem;}
.ssl-card--form input[type=text],.ssl-card--form input[type=url],.ssl-card--form input[type=file],.ssl-card--form textarea,.ssl-card--form select{border:1px solid #d0d5dd;border-radius:10px;padding:.55rem .75rem;background:#f8fafc;color:#1f2937;font-size:.95rem;}
.ssl-card--form textarea{min-height:110px;resize:vertical;}
.ssl-card--form input[type=file]{padding:.45rem;}
.ssl-card--form input[type=checkbox]{margin-left:6px;transform:scale(1.1);}
.ssl-card--form .ssl-note{margin-top:4px;}
.ssl-note{font-size:.85rem;color:#64748b;}
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
}
.ssl-err{color:#b00020;font-size:.85rem;}
CSS;
        wp_register_style('ssl-expiry-manager', false);
        wp_enqueue_style('ssl-expiry-manager');
        wp_add_inline_style('ssl-expiry-manager', $css);
        $js = <<<'JS'
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
    private function fmt_date($ts){ return $ts ? date_i18n('Y-m-d', $ts) : ''; }
    private function url_btn($u){ if(!$u) return ''; $u=esc_url($u); return "<a class='ssl-btn ssl-btn-outline' target='_blank' rel='noopener' href='{$u}'>פתיחת אתר</a>"; }

    public function shortcode_table($atts = []) {
        $a = shortcode_atts(['trash_url' => site_url('/?page=ssl-trash')], $atts);
        $is_create_hidden = empty($_GET['ssl_new']);
        $create_attr = $is_create_hidden ? ' hidden' : '';
        $admin_email = sanitize_email(get_option('admin_email'));
        $export_url = esc_url(site_url('?ssl_action='.self::EXPORT_ACTION));
        $refresh_url = esc_url(remove_query_arg('ssl_new'));
        ob_start();
        echo "<div class='ssl-manager'>";
        echo "<div class='ssl-manager__header'>";
        echo "<div class='ssl-manager__title'><h2>ניהול תאריכי תפוגת דומיינים</h2>";
        if ($admin_email) {
            echo "<div class='ssl-manager__subtitle'>".esc_html($admin_email)."</div>";
        }
        echo "</div>";
        echo "<div class='ssl-manager__header-actions'>";
        echo "<a class='ssl-btn ssl-btn-primary' data-ssl-toggle='create' href='".esc_url(add_query_arg('ssl_new','1'))."'>הוסף רשומה</a>";
        echo "<a class='ssl-btn ssl-btn-outline' href='".esc_url($a['trash_url'])."'>סל מחזור</a>";
        echo "</div></div>";

        echo "<div class='ssl-toolbar'>";
        echo "<div class='ssl-toolbar__group'><a class='ssl-btn ssl-btn-surface' href='{$export_url}'>ייצוא CSV</a>";
        echo "<a class='ssl-btn ssl-btn-surface' href='{$refresh_url}'>רענון</a></div>";
        echo "<form class='ssl-toolbar__import' method='post' action='".esc_url(admin_url('admin-post.php'))."' enctype='multipart/form-data'>".$this->nonce_field().""
              ."  <input type='hidden' name='action' value='".esc_attr(self::IMPORT_ACTION)."' />"
              ."  <input type='file' name='csv' accept='.csv' required />"
              ."  <button class='ssl-btn ssl-btn-primary' type='submit'>ייבוא CSV</button>"
              ."</form>";
        echo "<div class='ssl-toolbar__group ssl-toolbar__group--end'><span class='ssl-note'>ייבוא קובץ יעדכן רשומות קיימות או ייצור חדשות.</span></div>";
        echo "</div>";

        echo "<div class='ssl-card ssl-card--form' data-ssl-create{$create_attr}>";
        echo "<div class='ssl-card__header'><h3>הוספת רשומה חדשה</h3><button type='button' class='ssl-btn ssl-btn-ghost' data-ssl-toggle='create' title='סגירת הטופס' aria-label='סגירת הטופס'>&#10005;</button></div>";
        echo "<form method='post' action='".esc_url(admin_url('admin-post.php'))."' enctype='multipart/form-data'>".$this->nonce_field().""
              ."  <input type='hidden' name='action' value='".esc_attr(self::SAVE_ACTION)."' />"
              ."  <input type='hidden' name='post_id' value='0' />"
              ."  <div class='ssl-card__body'>"
              ."    <label>שם הלקוח<input type='text' name='client_name' required></label>"
              ."    <label>אתר (URL)<input type='url' name='site_url' placeholder='https://example.com'></label>"
              ."    <label>תאריך תפוגה (YYYY-MM-DD) <input type='text' name='expiry_date' placeholder='2026-12-31'></label>"
              ."    <label>ליקוט <select name='source'><option value='manual'>ידני</option><option value='auto'>אוטומטי</option></select></label>"
              ."    <label class='ssl-card__inline'><span>בדיקה דרך Agent בלבד</span><input type='checkbox' name='agent_only' value='1'></label>"
              ."    <label>הערות<textarea name='notes' rows='3'></textarea></label>"
              ."    <label>תמונות<input type='file' name='images[]' multiple accept='image/*'></label>"
              ."  </div>"
              ."  <div class='ssl-card__footer'><button class='ssl-btn ssl-btn-primary' type='submit'>שמור</button></div>"
              ."</form>"
              ."<div class='ssl-note'>בדיקה אוטומטית יומית לאתרים ציבוריים. פנימיים יסומנו Agent בלבד.</div>"
              ."</div>";

        $q = new WP_Query(['post_type'=> self::CPT,'post_status'=> ['publish','draft','pending'],'posts_per_page'=> -1,'orderby'=>'title','order'=>'ASC']);

        echo "<table class='ssl-table'><thead><tr>"
                ."<th>שם הלקוח</th><th>אתר</th><th>פתיחה</th><th>תאריך תפוגה</th><th>ימים</th><th>ליקוט</th><th>הערות</th><th>תמונות</th><th>שגיאה</th><th>פעולות</th>"
              ."</tr></thead><tbody>";

        if ($q->have_posts()){
            while($q->have_posts()){ $q->the_post();
                $id=get_the_ID();
                $client=get_post_meta($id,'client_name',true);
                $url=get_post_meta($id,'site_url',true);
                $expiry=(int)get_post_meta($id,'expiry_ts',true);
                $src=get_post_meta($id,'source',true);
                $notes=get_post_meta($id,'notes',true);
                $imgs=get_post_meta($id,'images',true); if(!is_array($imgs)) $imgs=[];
                $err=get_post_meta($id,'last_error',true);
                $days=$this->days_left($expiry);
                $badge=$this->badge_class($days);
                $days_txt=$days===null?'':$days;

                echo "<tr>";
                echo "<td>".esc_html($client)."</td>";
                echo "<td><a target='_blank' rel='noopener' href='".esc_url($url)."'>".esc_html($url)."</a></td>";
                echo "<td>".$this->url_btn($url)."</td>";
                echo "<td>".$this->fmt_date($expiry)."</td>";
                echo "<td><span class='ssl-badge {$badge}'>".$days_txt."</span></td>";
                echo "<td>".esc_html($src)."</td>";
                echo "<td>".nl2br(esc_html($notes))."</td>";
                echo "<td>"; foreach($imgs as $aid){ $srcImg=wp_get_attachment_image_url($aid,'thumbnail'); if($srcImg) echo "<a target='_blank' href='".esc_url(wp_get_attachment_url($aid))."'><img src='".esc_url($srcImg)."' style='max-width:60px;max-height:60px;margin:2px;border-radius:8px;box-shadow:0 4px 10px rgba(15,23,42,.12)'/></a>"; } echo "</td>";
                echo "<td>".($err ? "<span class='ssl-err'>".esc_html($err)."</span>" : "")."</td>";
                echo "<td class='ssl-actions'>";
                echo "<a class='ssl-btn ssl-btn-surface' href='javascript:void(0)' data-ssl-edit='".esc_attr($id)."'>עריכה</a>";
                $del_url=esc_url(admin_url('admin-post.php'));
                echo "<form method='post' action='{$del_url}'>".$this->nonce_field().""
                        ."<input type='hidden' name='action' value='".esc_attr(self::DELETE_ACTION)."' />"
                        ."<input type='hidden' name='post_id' value='".esc_attr($id)."' />"
                        ."<button class='ssl-btn ssl-btn-danger' type='submit' onclick=\"return confirm('להעביר לסל מחזור?')\">מחיקה</button>"
                      ."</form>";
                echo "</td></tr>";

                echo "<tr data-ssl-form='".esc_attr($id)."' class='ssl-table__edit-row' hidden><td colspan='10'><div class='ssl-card ssl-card--form'>"
                        ."<div class='ssl-card__header'><h3>עריכת רשומה</h3><button type='button' class='ssl-btn ssl-btn-ghost' data-ssl-edit='".esc_attr($id)."' title='סגירת עריכה' aria-label='סגירת עריכה'>&#10005;</button></div>"
                        ."<form method='post' action='".esc_url(admin_url('admin-post.php'))."' enctype='multipart/form-data'>".$this->nonce_field().""
                        ."<input type='hidden' name='action' value='".esc_attr(self::SAVE_ACTION)."' />"
                        ."<input type='hidden' name='post_id' value='".esc_attr($id)."' />"
                        ."<div class='ssl-card__body'>"
                        ."<label>שם הלקוח<input type='text' name='client_name' value='".esc_attr($client)."'></label>"
                        ."<label>אתר (URL)<input type='url' name='site_url' value='".esc_attr($url)."'></label>"
                        ."<label>תאריך תפוגה (YYYY-MM-DD) <input type='text' name='expiry_date' value='".esc_attr($this->fmt_date($expiry))."'></label>"
                        ."<label>ליקוט <select name='source'><option value='manual' ".selected($src,'manual',false).">ידני</option><option value='auto' ".selected($src,'auto',false).">אוטומטי</option></select></label>"
                        ."<label class='ssl-card__inline'><span>בדיקה דרך Agent בלבד</span><input type='checkbox' name='agent_only' value='1' ".checked((bool)get_post_meta($id,'agent_only',true),true,false)."></label>"
                        ."<label>הערות<textarea name='notes' rows='3'>".esc_textarea($notes)."</textarea></label>"
                        ."<label>תמונות (להוסיף חדשות) <input type='file' name='images[]' multiple accept='image/*'></label>"
                        ."</div>"
                        ."<div class='ssl-card__footer'><button class='ssl-btn ssl-btn-primary' type='submit'>שמור</button></div>"
                        ."</form>"
                        ."</div></td></tr>";
            }
            wp_reset_postdata();
        } else {
            echo "<tr><td class='ssl-empty' colspan='10'>אין נתונים</td></tr>";
        }
        echo "</tbody></table>";
        echo "<div class='ssl-note'>צבעים: ירוק &gt; 90. צהוב 31–90. אדום ≤ 30.</div>";
        echo "</div>";
        return ob_get_clean();
    }
    public function shortcode_trash($atts = []) {
        $a = shortcode_atts(['main_url' => site_url('/')], $atts);
        $q = new WP_Query(['post_type'=> self::CPT,'post_status'=> 'trash','posts_per_page'=> -1,'orderby'=>'modified','order'=>'DESC']);
        ob_start();
        echo "<div class='ssl-manager'>";
        echo "<div class='ssl-manager__header'>";
        echo "<div class='ssl-manager__title'><h2>סל מחזור</h2><div class='ssl-manager__subtitle'>רשומות שנמחקו נשמרות למשך 90 יום לפני מחיקה סופית.</div></div>";
        echo "<div class='ssl-manager__header-actions'><a class='ssl-btn ssl-btn-outline' href='".esc_url($a['main_url'])."'>חזרה לטבלה</a></div>";
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
        $a = shortcode_atts(['main_url'=>site_url('/'),'trash_url'=>site_url('/?page=ssl-trash')], $atts);
        $export_url = site_url('?ssl_action='.self::EXPORT_ACTION);
        $import_action = esc_attr(self::IMPORT_ACTION);
        ob_start();
        echo "<div class='ssl-manager'>";
        echo "<div class='ssl-manager__header'>";
        echo "<div class='ssl-manager__title'><h2>פעולות מהירות</h2><div class='ssl-manager__subtitle'>ניהול זריז של רשומות SSL</div></div>";
        echo "<div class='ssl-manager__header-actions'>";
        echo "<a class='ssl-btn ssl-btn-primary' href='".esc_url(add_query_arg('ssl_new','1',$a['main_url']))."'>הוסף רשומה</a>";
        echo "<a class='ssl-btn ssl-btn-outline' href='".esc_url($a['trash_url'])."'>סל מחזור</a>";
        echo "</div></div>";
        echo "<div class='ssl-toolbar'>";
        echo "<div class='ssl-toolbar__group'><a class='ssl-btn ssl-btn-surface' href='".esc_url($export_url)."'>ייצוא CSV</a>";
        echo "<a class='ssl-btn ssl-btn-surface' href='".esc_url($a['main_url'])."'>לטבלה הראשית</a></div>";
        echo "<form class='ssl-toolbar__import' method='post' action='".esc_url(admin_url('admin-post.php'))."' enctype='multipart/form-data'>".$this->nonce_field().""
                ."<input type='hidden' name='action' value='{$import_action}' />"
                ."<input type='file' name='csv' accept='.csv' required />"
                ."<button class='ssl-btn ssl-btn-primary' type='submit'>ייבוא CSV</button>"
              ."</form>";
        echo "</div>";
        echo "</div>";
        return ob_get_clean();
    }
    public function shortcode_token() {
        $tok = get_option(self::OPTION_TOKEN);
        if (!$tok) { $tok = wp_generate_password(32,false,false); update_option(self::OPTION_TOKEN, $tok); }
        $action = esc_attr('ssl_regen_token');
        ob_start();
        echo "<div class='ssl-manager'>";
        echo "<div class='ssl-card'>";
        echo "<div class='ssl-card__header'><h3>Token ל-Agent</h3></div>";
        echo "<div class='ssl-card__body ssl-token-row'>";
        echo "<input class='ssl-token-input' type='text' readonly value='".esc_attr($tok)."'>";
        echo "<form class='ssl-token-form' method='post' action='".esc_url(admin_url('admin-post.php'))."'>".$this->nonce_field().""
                ."<input type='hidden' name='action' value='{$action}'>"
                ."<button class='ssl-btn ssl-btn-primary' type='submit' onclick=\"return confirm('ליצור טוקן חדש?')\">צור טוקן חדש</button>"
              ."</form>";
        echo "</div>";
        echo "<div class='ssl-note'>Header: <code>X-SSL-Token</code> = הערך לעיל</div>";
        echo "</div>";
        echo "</div>";
        return ob_get_clean();
    }
    public function shortcode_token_page() {
        $tok = get_option(self::OPTION_TOKEN);
        if (!$tok) { $tok = wp_generate_password(32,false,false); update_option(self::OPTION_TOKEN, $tok); }
        $action = esc_attr('ssl_regen_token');
        $main_url  = "https://kbtest.macomp.co.il/?p=9427";
        $trash_url = "https://kbtest.macomp.co.il/?p=9441";
        ob_start();
        echo "<div class='ssl-manager'>";
        echo "<div class='ssl-card'>";
        echo "<div class='ssl-card__header'><h2>ניהול Token לסוכן SSL</h2></div>";
        echo "<div class='ssl-card__body'>";
        echo "<p>הטוקן נדרש לחיבור הסוכן המקומי למערכת.</p>";
        echo "<div class='ssl-token-row'>";
        echo "<input class='ssl-token-input' type='text' readonly value='".esc_attr($tok)."'>";
        echo "<form class='ssl-token-form' method='post' action='".esc_url(admin_url('admin-post.php'))."'>".$this->nonce_field().""
                ."<input type='hidden' name='action' value='{$action}'>"
                ."<button class='ssl-btn ssl-btn-primary' type='submit' onclick=\"return confirm('ליצור טוקן חדש?')\">צור טוקן חדש</button>"
              ."</form>";
        echo "</div>";
        echo "<div class='ssl-note'>הסוכן שולח Header בשם <code>X-SSL-Token</code> עם הערך לעיל.</div>";
        echo "</div>";
        echo "<div class='ssl-card__footer ssl-card__footer--links'>";
        echo "<a class='ssl-btn ssl-btn-surface' href='".esc_url($main_url)."'>חזרה לטבלה הראשית</a>";
        echo "<a class='ssl-btn ssl-btn-outline' href='".esc_url($trash_url)."'>מעבר לסל מחזור</a>";
        echo "</div>";
        echo "</div>";
        echo "</div>";
        return ob_get_clean();
    }
    public function handle_regen_token() {
        $this->check_nonce();
        $tok = wp_generate_password(32,false,false);
        update_option(self::OPTION_TOKEN, $tok);
        wp_safe_redirect( wp_get_referer() ?: home_url('/') ); exit;
    }

    public function handle_save() {
        $this->check_nonce();
        $post_id=intval($_POST['post_id'] ?? 0);
        $client=sanitize_text_field($_POST['client_name'] ?? '');
        $site=$this->sanitize_url($_POST['site_url'] ?? '');
        $expiry_date=sanitize_text_field($_POST['expiry_date'] ?? '');
        $source=in_array($_POST['source'] ?? 'manual',['manual','auto'],true)?$_POST['source']:'manual';
        $notes=sanitize_textarea_field($_POST['notes'] ?? '');
        $agent_only = !empty($_POST['agent_only']) ? 1 : 0;

        $expiry_ts=null; if($expiry_date){ $t=strtotime($expiry_date.' 00:00:00'); if($t) $expiry_ts=$t; }

        if($post_id){ wp_update_post(['ID'=>$post_id,'post_title'=>$client?:'SSL Item']); }
        else { $post_id=wp_insert_post(['post_type'=>self::CPT,'post_status'=>'publish','post_title'=>$client?:'SSL Item']); }

        if($post_id && !is_wp_error($post_id)){
            update_post_meta($post_id,'client_name',$client);
            update_post_meta($post_id,'site_url',$site);
            if($expiry_ts) update_post_meta($post_id,'expiry_ts',$expiry_ts);
            update_post_meta($post_id,'source',$source);
            update_post_meta($post_id,'notes',$notes);
            update_post_meta($post_id,'agent_only',$agent_only);

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
        }
        wp_safe_redirect( wp_get_referer() ?: home_url('/') ); exit;
    }
    public function handle_delete(){ $this->check_nonce(); $id=intval($_POST['post_id']??0); if($id) wp_trash_post($id); wp_safe_redirect( wp_get_referer() ?: home_url('/') ); exit; }
    public function handle_restore(){ $this->check_nonce(); $id=intval($_POST['post_id']??0); if($id) wp_untrash_post($id); wp_safe_redirect( wp_get_referer() ?: home_url('/') ); exit; }

    public function handle_export() {
        $filename='ssl-export-'.date('Ymd-His').'.csv';
        header('Content-Type: text/csv; charset=utf-8');
        header('Content-Disposition: attachment; filename='.$filename);
        $out=fopen('php://output','w');
        fputcsv($out,['client_name','site_url','expiry_date','source','notes','image_urls','agent_only']);
        $q=new WP_Query(['post_type'=>self::CPT,'post_status'=>['publish','draft','pending','trash'],'posts_per_page'=>-1]);
        if($q->have_posts()){
            while($q->have_posts()){ $q->the_post();
                $id=get_the_ID();
                $client=get_post_meta($id,'client_name',true);
                $site=get_post_meta($id,'site_url',true);
                $expiry=get_post_meta($id,'expiry_ts',true);
                $src=get_post_meta($id,'source',true);
                $notes=get_post_meta($id,'notes',true);
                $agent_only=(int)get_post_meta($id,'agent_only',true);
                $imgs=get_post_meta($id,'images',true); $urls=[];
                if(is_array($imgs)) foreach($imgs as $aid){ $u=wp_get_attachment_url($aid); if($u) $urls[]=$u; }
                fputcsv($out,[$client,$site,$expiry?date('Y-m-d',$expiry):'',$src,$notes,implode('|',$urls),$agent_only]);
            }
            wp_reset_postdata();
        }
        fclose($out); exit;
    }

    public function handle_import() {
        $this->check_nonce();
        if(empty($_FILES['csv']) || $_FILES['csv']['error']!==UPLOAD_ERR_OK) wp_die('קובץ CSV לא תקין');
        $fh=fopen($_FILES['csv']['tmp_name'],'r'); if(!$fh) wp_die('כשל בקריאת קובץ');
        $header=fgetcsv($fh);
        while(($row=fgetcsv($fh))!==false){
            $row=array_pad($row,7,''); list($client,$site,$exp,$src,$notes,$image_urls,$agent_only)=$row;
            $pid=wp_insert_post(['post_type'=>self::CPT,'post_status'=>'publish','post_title'=>$client?:'SSL Item']); if(is_wp_error($pid)) continue;
            update_post_meta($pid,'client_name',sanitize_text_field($client));
            update_post_meta($pid,'site_url',$this->sanitize_url($site));
            $ts=$exp?strtotime($exp.' 00:00:00'):null; if($ts) update_post_meta($pid,'expiry_ts',$ts);
            update_post_meta($pid,'source', in_array($src,['manual','auto'],true)?$src:'manual');
            update_post_meta($pid,'notes',sanitize_textarea_field($notes));
            update_post_meta($pid,'agent_only',(int)!!$agent_only);
        }
        fclose($fh);
        wp_safe_redirect( wp_get_referer() ?: home_url('/') ); exit;
    }

    public function ensure_cron(){ if(!wp_next_scheduled(self::CRON_HOOK)) wp_schedule_event(time()+300,'daily',self::CRON_HOOK); }
    public function cron_check_all() {
        $q=new WP_Query(['post_type'=>self::CPT,'post_status'=>['publish','draft','pending'],'posts_per_page'=>-1,'meta_query'=>[['key'=>'agent_only','compare'=>'!=','value'=>1]]]);
        if($q->have_posts()){
            while($q->have_posts()){ $q->the_post();
                $id=get_the_ID(); $url=get_post_meta($id,'site_url',true); if(!$url) continue;
                $exp_ts=$this->fetch_ssl_expiry_ts($url);
                if($exp_ts){ update_post_meta($id,'expiry_ts',$exp_ts); update_post_meta($id,'source','auto'); delete_post_meta($id,'last_error'); }
            }
            wp_reset_postdata();
        }
    }
    private function fetch_ssl_expiry_ts($url){
        $p=wp_parse_url($url); if(!$p || empty($p['host'])) return null;
        $host=$p['host']; $port=isset($p['port'])?intval($p['port']):443;
        $ctx=stream_context_create(['ssl'=>['capture_peer_cert'=>true,'verify_peer'=>false,'verify_peer_name'=>false,'SNI_enabled'=>true,'peer_name'=>$host]]);
        $client=@stream_socket_client("ssl://{$host}:{$port}",$errno,$errstr,10,STREAM_CLIENT_CONNECT,$ctx);
        if(!$client) return null;
        $params=stream_context_get_params($client);
        if(empty($params['options']['ssl']['peer_certificate'])) return null;
        $cert=$params['options']['ssl']['peer_certificate'];
        $parsed=openssl_x509_parse($cert);
        if(!$parsed || empty($parsed['validTo_time_t'])) return null;
        return (int)$parsed['validTo_time_t'];
    }

    public function register_rest() {
        register_rest_route('ssl/v1','/tasks',['methods'=>'GET','permission_callback'=>'__return_true','callback'=>[$this,'rest_tasks']]);
        register_rest_route('ssl/v1','/report',['methods'=>'POST','permission_callback'=>'__return_true','callback'=>[$this,'rest_report']]);
    }
    private function rest_auth($req){
        $token=$req->get_header('x-ssl-token') ?: '';
        $expected=get_option(self::OPTION_TOKEN) ?: '';
        if(!$expected || !$token || !hash_equals($expected,$token)){
            return new WP_Error('forbidden','invalid token',['status'=>403]);
        }
        return true;
    }
    public function rest_tasks(WP_REST_Request $req){
        $auth=$this->rest_auth($req); if(is_wp_error($auth)) return $auth;
        $limit=min(100,max(1,intval($req->get_param('limit') ?: 50)));
        $force=intval($req->get_param('force') ?: 0)===1;
        $now=time(); $stale=$now-DAY_IN_SECONDS;
        $meta_q=[['key'=>'site_url','compare'=>'EXISTS']];
        if(!$force){ $meta_q[]=['key'=>'expiry_ts_checked_at','compare'=>'<','value'=>(string)$stale]; }
        $q=new WP_Query(['post_type'=>self::CPT,'post_status'=>['publish','draft','pending'],'posts_per_page'=>$limit,'orderby'=>'modified','order'=>'DESC','meta_query'=>$meta_q]);
        $items=[];
        while($q->have_posts()){ $q->the_post();
            $id=get_the_ID();
            $url=get_post_meta($id,'site_url',true);
            if(!$url) continue;
            $items[]=['id'=>$id,'client_name'=>(string)get_post_meta($id,'client_name',true),'site_url'=>(string)$url];
            update_post_meta($id,'expiry_ts_checked_at', time());
        }
        wp_reset_postdata();
        return new WP_REST_Response(['tasks'=>$items,'count'=>count($items)],200);
    }
    public function rest_report(WP_REST_Request $req){
        $auth=$this->rest_auth($req); if(is_wp_error($auth)) return $auth;
        $data=$req->get_json_params();
        $rows=is_array($data['results']??null)?$data['results']:[];
        foreach($rows as $row){
            $id=intval($row['id']??0); if(!$id) continue;
            if(!empty($row['expiry_ts'])){ update_post_meta($id,'expiry_ts',intval($row['expiry_ts'])); update_post_meta($id,'source','auto'); delete_post_meta($id,'last_error'); }
            if(!empty($row['error'])){ update_post_meta($id,'last_error',sanitize_text_field($row['error'])); }
            update_post_meta($id,'expiry_ts_checked_at', time());
        }
        return new WP_REST_Response(['ok'=>true,'updated'=>count($rows)],200);
    }

    public function settings_page(){
        add_options_page('SSL Expiry API','SSL Expiry API','manage_options','ssl-expiry-api',function(){
            if(isset($_POST[self::OPTION_TOKEN]) && check_admin_referer('ssl_em_save_token')){
                update_option(self::OPTION_TOKEN, sanitize_text_field($_POST[self::OPTION_TOKEN]));
                echo '<div class="updated"><p>נשמר</p></div>';
            }
            $tok=get_option(self::OPTION_TOKEN) ?: wp_generate_password(32,false,false);
            echo '<div class="wrap"><h1>SSL Expiry API</h1><form method="post">';
            wp_nonce_field('ssl_em_save_token');
            echo '<p><label>API Token <input type="text" name="'.esc_attr(self::OPTION_TOKEN).'" value="'.esc_attr($tok).'" style="width:420px"></label></p>';
            echo '<p><button class="button button-primary">שמור</button></p>';
            echo '<p>הסוכן ישלח Header בשם <code>X-SSL-Token</code> עם הערך הזה.</p>';
            echo '</form></div>';
        });
    }
    public function on_activate(){
        if(!get_option(self::OPTION_TOKEN)) add_option(self::OPTION_TOKEN, wp_generate_password(32,false,false));
        if(!get_page_by_path('ssl-trash')){
            wp_insert_post(['post_title'=>'סל מחזור SSL','post_name'=>'ssl-trash','post_type'=>'page','post_status'=>'publish','post_content'=>'[ssl_trash]']);
        }
    }
    public function route_export_helper(){
        if(!empty($_GET['ssl_action']) && $_GET['ssl_action']==self::EXPORT_ACTION){
            do_action('admin_post_nopriv_'.self::EXPORT_ACTION); exit;
        }
    }
}
new SSL_Expiry_Manager_AIO();
