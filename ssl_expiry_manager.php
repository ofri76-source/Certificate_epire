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
    const OPTION_REMOTE = 'ssl_em_remote_client';
    const ADD_TOKEN_ACTION    = 'ssl_add_token';
    const MANAGE_TOKEN_ACTION = 'ssl_manage_token';
    const PAGE_MAIN_FALLBACK  = 'https://kbtest.macomp.co.il/?p=9427';
    const PAGE_TRASH_FALLBACK = 'https://kbtest.macomp.co.il/?p=9441';
    const PAGE_TOKEN_FALLBACK = 'https://kbtest.macomp.co.il/?p=9447';

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
            'endpoint' => '',
            'auth_token' => '',
            'verify' => 1,
            'timeout' => 20,
            'retries' => 1,
        ];
        $settings = wp_parse_args($saved, $defaults);
        $settings['endpoint'] = trim((string)$settings['endpoint']);
        $settings['auth_token'] = trim((string)$settings['auth_token']);
        $settings['enabled'] = (int)!empty($settings['enabled']);
        $settings['verify'] = (int)!empty($settings['verify']);
        $settings['timeout'] = max(5, min(120, (int)$settings['timeout']));
        $settings['retries'] = max(0, min(5, (int)$settings['retries']));
        return $settings;
    }

    private function remote_client_is_ready($settings = null){
        if($settings === null){
            $settings = $this->get_remote_client_settings();
        }
        if(empty($settings['enabled'])){
            return false;
        }
        if(empty($settings['endpoint']) || stripos($settings['endpoint'], 'http') !== 0){
            return false;
        }
        if(empty($settings['auth_token'])){
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
        $primary = $this->get_primary_token();
        if(!$primary || empty($primary['token'])){
            return false;
        }
        $token_value = (string)$primary['token'];
        $endpoint = trailingslashit($settings['endpoint']).'api/check';
        $payload = [
            'request_id' => 'wp'.wp_generate_password(12, false, false),
            'id' => (int)$post_id,
            'site_url' => (string)$url,
            'callback' => rest_url('ssl/v1/report'),
            'token' => $token_value,
            'context' => $context,
            'report_timeout' => (int)$settings['timeout'],
        ];
        $args = [
            'headers' => [
                'Authorization' => 'Bearer '.$settings['auth_token'],
                'Content-Type'  => 'application/json',
                'Accept'        => 'application/json',
            ],
            'body' => wp_json_encode($payload),
            'timeout' => (int)$settings['timeout'],
            'sslverify' => !empty($settings['verify']),
        ];
        $attempts = max(1, 1 + (int)$settings['retries']);
        $last_message = '';
        for($i=0;$i<$attempts;$i++){
            $response = wp_remote_post($endpoint, $args);
            if(is_wp_error($response)){
                $last_message = 'Remote dispatch failed: '.$response->get_error_message();
            } else {
                $code = (int)wp_remote_retrieve_response_code($response);
                if($code >= 200 && $code < 300){
                    update_post_meta($post_id, 'expiry_ts_checked_at', time());
                    delete_post_meta($post_id, 'last_error');
                    $this->mark_token_online($primary['id']);
                    return true;
                }
                $body = wp_remote_retrieve_body($response);
                $last_message = 'Remote dispatch HTTP '.$code;
                if($body){
                    $last_message .= ': '.wp_strip_all_tags($body);
                }
            }
            if($i < $attempts - 1){
                usleep(200000);
            }
        }
        if($last_message){
            update_post_meta($post_id, 'last_error', $last_message);
        }
        $token_state = $this->mark_token_offline($primary['id'], $last_message ?: 'שגיאת תקשורת לא ידועה');
        if($token_state){
            $this->maybe_notify_token_down($token_state, $last_message ?: 'שגיאת תקשורת לא ידועה');
        }
        return false;
    }

    public function shortcode_table($atts = []) {
        $default_trash = $this->resolve_trash_page_url();
        $default_token = $this->resolve_token_page_url();
        $a = shortcode_atts([
            'trash_url' => $default_trash,
            'token_url' => $default_token,
        ], $atts);
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
        echo "<a class='ssl-btn ssl-btn-outline' href='".esc_url($a['token_url'])."'>ניהול טוקנים</a>";
        echo "</div></div>";

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
        echo "<div class='ssl-footer-tools'>";
        echo "  <div class='ssl-toolbar ssl-toolbar--bottom'>";
        echo "    <div class='ssl-toolbar__group'><a class='ssl-btn ssl-btn-surface' href='{$export_url}'>ייצוא CSV</a>";
        echo "    <a class='ssl-btn ssl-btn-surface' href='{$refresh_url}'>רענון</a></div>";
        echo "    <form class='ssl-toolbar__import' method='post' action='".esc_url(admin_url('admin-post.php'))."' enctype='multipart/form-data'>".$this->nonce_field().""
             ."      <input type='hidden' name='action' value='".esc_attr(self::IMPORT_ACTION)."' />"
             ."      <input type='file' name='csv' accept='.csv' required />"
             ."      <button class='ssl-btn ssl-btn-primary' type='submit'>ייבוא CSV</button>"
             ."    </form>";
        echo "    <div class='ssl-toolbar__group ssl-toolbar__group--end'><span class='ssl-note'>ייבוא קובץ יעדכן רשומות קיימות או ייצור חדשות.</span></div>";
        echo "  </div>";
        echo "</div>";
        echo "</div>";
        return ob_get_clean();
    }
    public function shortcode_trash($atts = []) {
        $main_default = $this->resolve_main_page_url();
        $a = shortcode_atts(['main_url' => $main_default], $atts);
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
        $main_default = $this->resolve_main_page_url();
        $default_token = $this->resolve_token_page_url();
        $default_trash = $this->resolve_trash_page_url();
        $a = shortcode_atts([
            'main_url'=>$main_default,
            'trash_url'=>$default_trash,
            'token_url'=>$default_token,
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
                ."<button class='ssl-btn ssl-btn-primary' type='submit' onclick=\"return confirm('ליצור טוקן חדש?')\">צור טוקן חדש</button>"
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
        $a = shortcode_atts([
            'main_url'  => $main_default,
            'trash_url' => $trash_default,
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
                echo "<button class='ssl-btn ssl-btn-surface' type='submit' form='".esc_attr($form_id)."' name='sub_action' value='regen' onclick=\"return confirm('ליצור טוקן חדש?')\">צור טוקן חדש</button>";
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
    public function handle_regen_token() {
        $this->check_nonce();
        $tokens = $this->ensure_default_token();
        $token_id = sanitize_text_field($_POST['token_id'] ?? '');
        if(!$token_id && !empty($tokens)){
            $token_id = $tokens[0]['id'];
        }
        $updated = false;
        foreach($tokens as &$token){
            if($token['id'] === $token_id){
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
        $tokens[] = [
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
        $this->save_tokens($tokens);
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
        foreach($tokens as $index => &$token){
            if($token['id'] !== $token_id){
                continue;
            }
            if($sub === 'delete'){
                unset($tokens[$index]);
                $changed = true;
                break;
            }
            if(in_array($sub, ['regen','update'], true)){
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
                $changed = true;
            }
            break;
        }
        unset($token);
        if($changed){
            $tokens = array_values($tokens);
            if(empty($tokens)){
                $tokens[] = [
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
            }
            $this->save_tokens($tokens);
        }
        wp_safe_redirect( wp_get_referer() ?: home_url('/') ); exit;
    }

    public function handle_save_remote_client(){
        if(!current_user_can('manage_options')){
            wp_die('אין לך הרשאה לעדכן הגדרות אלו');
        }
        check_admin_referer('ssl_remote_client');
        $enabled = !empty($_POST['remote_enabled']) ? 1 : 0;
        $endpoint = esc_url_raw(trim($_POST['remote_endpoint'] ?? ''));
        $auth_token = sanitize_text_field($_POST['remote_auth_token'] ?? '');
        $verify = !empty($_POST['remote_verify']) ? 1 : 0;
        $timeout = max(5, min(120, intval($_POST['remote_timeout'] ?? 20)));
        $retries = max(0, min(5, intval($_POST['remote_retries'] ?? 1)));
        $settings = [
            'enabled' => $enabled,
            'endpoint' => $endpoint,
            'auth_token' => $auth_token,
            'verify' => $verify,
            'timeout' => $timeout,
            'retries' => $retries,
        ];
        update_option(self::OPTION_REMOTE, $settings);
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
            if($site){
                $this->dispatch_remote_check($post_id, $site, 'manual-save');
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
        $settings = $this->get_remote_client_settings();
        $remote_ready = $this->remote_client_is_ready($settings);
        $meta_query = [];
        if(!$remote_ready){
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
                $exp_ts=$this->fetch_ssl_expiry_ts($url);
                if($exp_ts){
                    update_post_meta($id,'expiry_ts',$exp_ts);
                    update_post_meta($id,'source','auto');
                    delete_post_meta($id,'last_error');
                }
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
    }
    private function rest_auth($req){
        $token=$req->get_header('x-ssl-token') ?: '';
        if(!$token){
            return new WP_Error('forbidden','invalid token',['status'=>403]);
        }
        $tokens=$this->ensure_default_token();
        foreach($tokens as $stored){
            if(!empty($stored['token']) && hash_equals($stored['token'], $token)){
                $updated = $this->mark_token_online($stored['id']);
                return ['token' => $updated ?: $stored];
            }
        }
        return new WP_Error('forbidden','invalid token',['status'=>403]);
    }
    public function rest_tasks(WP_REST_Request $req){
        $auth=$this->rest_auth($req); if(is_wp_error($auth)) return $auth;
        $limit=min(100,max(1,intval($req->get_param('limit') ?: 50)));
        $force=intval($req->get_param('force') ?: 0)===1;
        $items=$this->collect_rest_tasks($limit,$force,null);
        return new WP_REST_Response(['tasks'=>$items,'count'=>count($items)],200);
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
        $items=$this->collect_rest_tasks($limit,$force,$agent_filter);
        $callback=rest_url('ssl/v1/report');
        $token_value=isset($auth['token']['token']) ? (string)$auth['token']['token'] : '';
        $jobs=[];
        foreach($items as $item){
            $jobs[]=$item + [
                'callback'=>$callback,
                'token'=>$token_value,
            ];
        }
        return new WP_REST_Response([
            'tasks'=>$jobs,
            'count'=>count($jobs),
            'callback'=>$callback,
            'token'=>$token_value,
        ],200);
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
            echo '<p>כל קריאת REST חייבת לכלול Header בשם <code>X-SSL-Token</code>.</p>';
            echo '<hr />';
            echo '<h2>הגדרות קליינט מרוחק</h2>';
            if($remote_ready){
                echo '<p><span style="color:#0a7a0a;font-weight:600;">הקליינט המרוחק פעיל.</span> כל בקשת בדיקה תשלח לכתובת המוגדרת להלן.</p>';
            } else {
                echo '<p><span style="color:#b91c1c;font-weight:600;">הקליינט המרוחק כבוי או לא הוגדר במלואו.</span> ברירת המחדל תהיה בדיקה ישירה מהשרת.</p>';
            }
            echo '<form method="post" action="'.esc_url(admin_url('admin-post.php')).'" class="ssl-remote-form">';
            wp_nonce_field('ssl_remote_client');
            echo '<input type="hidden" name="action" value="ssl_save_remote_client" />';
            echo '<table class="form-table" role="presentation"><tbody>';
            echo '<tr><th scope="row">הפעלת הקליינט</th><td><label><input type="checkbox" name="remote_enabled" value="1" '.checked(!empty($remote['enabled']),true,false).' /> הפעל העברה לשרת המרוחק</label></td></tr>';
            echo '<tr><th scope="row">כתובת שירות מרוחק</th><td><input type="text" class="regular-text" name="remote_endpoint" value="'.esc_attr($remote['endpoint']).'" placeholder="https://office-host:8443/" />';
            echo '<p class="description">השתמש בכתובת HTTPS של השירות שיוקם (למשל <code>https://192.168.1.50:8443/</code>).</p></td></tr>';
            echo '<tr><th scope="row">טוקן גישה לשירות</th><td><input type="text" class="regular-text" name="remote_auth_token" value="'.esc_attr($remote['auth_token']).'" />';
            echo '<p class="description">יש להזין את ה-Token שהוגדר בעת התקנת הסרוויס המרוחק באמצעות הסקריפט <code>remote_client_installer.py</code>.</p></td></tr>';
            echo '<tr><th scope="row">Timeout (שניות)</th><td><input type="number" min="5" max="120" name="remote_timeout" value="'.esc_attr($remote['timeout']).'" />';
            echo '<p class="description">זמן מקסימלי להמתנה לתשובת הסרוויס לפני מעבר לניסיון נוסף או לבדיקה מקומית.</p></td></tr>';
            echo '<tr><th scope="row">ניסיונות חוזרים</th><td><input type="number" min="0" max="5" name="remote_retries" value="'.esc_attr($remote['retries']).'" />';
            echo '<p class="description">כמות הניסיונות הנוספים לשליחת הבקשה (מעבר לניסיון הראשוני).</p></td></tr>';
            echo '<tr><th scope="row">בדיקת תוקף תעודה</th><td><label><input type="checkbox" name="remote_verify" value="1" '.checked(!empty($remote['verify']),true,false).' /> אמת את תעודת ה-SSL של השירות המרוחק</label>';
            echo '<p class="description">בטל אפשרות זו רק אם משתמשים בתעודה עצמית ואינך יכול להוסיף אותה לאמון השרת.</p></td></tr>';
            echo '</tbody></table>';
            echo '<p class="submit"><button type="submit" class="button button-primary">שמירת הגדרות</button></p>';
            echo '</form>';
            echo '<p class="description">לאחר ההתקנה, ניתן להריץ את הפקודה <code>python3 remote_client_installer.py --auth-token=TOKEN-מרוחק --listen-port=8443</code> על התחנה במשרד כדי להגדיר את הסרוויס ולספק כתובת לשדה לעיל.</p>';
            echo '</div>';
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
