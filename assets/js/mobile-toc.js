/**
 * kak4p0 Mobile Enhancements v3
 * 1) 인라인 TOC 자동 생성
 * 2) Chirpy TOC 트리거 버튼들 숨기기 (≡ + Contents)
 * 3) Post navigation 겹침 수정
 */
(function() {
  'use strict';
  document.addEventListener('DOMContentLoaded', function() {
    var isMobile = window.innerWidth < 992;

    /* ============================================
       1) 모바일 인라인 TOC
       ============================================ */
    if (isMobile) {
      var pc = document.querySelector('.post-content');
      if (pc) {
        var hh = pc.querySelectorAll('h2, h3, h4');
        if (hh.length >= 2) {
          hh.forEach(function(h, i) { if (!h.id) h.id = 'heading-' + i; });
          var s = '<details id="k-inline-toc"><summary>\uD83D\uDCD1 목차</summary><ul class="k-toc-list">';
          hh.forEach(function(h) {
            var t = h.textContent.replace(/#/g, '').trim();
            if (t) s += '<li class="k-toc-' + h.tagName.toLowerCase() + '"><a href="#' + h.id + '">' + t + '</a></li>';
          });
          s += '</ul></details>';
          pc.insertAdjacentHTML('afterbegin', s);
          var toc = document.getElementById('k-inline-toc');
          if (toc) toc.addEventListener('click', function(e) {
            var a = e.target.closest('a');
            if (!a) return;
            e.preventDefault();
            var el = document.getElementById(a.getAttribute('href').substring(1));
            if (el) window.scrollTo({ top: el.getBoundingClientRect().top + window.pageYOffset - 56, behavior: 'smooth' });
          });
        }
      }
    }

    /* ============================================
       2) Chirpy TOC 트리거 숨기기 (모바일)
       - 제목 옆 ≡ 아이콘
       - "Contents >" 버튼/텍스트
       ============================================ */
    if (isMobile) {
      // 방법: data-bs-target 속성으로 panel-wrapper를 여는 모든 요소 찾기
      document.querySelectorAll('[data-bs-target="#panel-wrapper"], [data-bs-target*="panel"], [data-bs-toggle="offcanvas"]').forEach(function(el) {
        // sidebar-trigger(햄버거)는 건드리지 않기
        if (el.id === 'sidebar-trigger') return;
        el.style.display = 'none';
      });

      // "Contents" 텍스트가 들어간 summary/button 찾기
      document.querySelectorAll('summary, button, .btn').forEach(function(el) {
        var txt = (el.textContent || '').trim().toLowerCase();
        if (txt.indexOf('contents') === 0 || txt === 'contents') {
          el.style.display = 'none';
          // 부모가 details면 details도 숨기기
          if (el.parentElement && el.parentElement.tagName === 'DETAILS') {
            el.parentElement.style.display = 'none';
          }
        }
      });

      // offcanvas-header 안의 닫기 버튼 등도 숨기기
      document.querySelectorAll('.offcanvas-header').forEach(function(el) {
        var parent = el.closest('#panel-wrapper') || el.closest('.offcanvas');
        if (parent && parent.id === 'panel-wrapper') {
          el.style.display = 'none';
        }
      });
    }

    /* ============================================
       3) Post navigation 겹침 수정 (모바일 + PC)
       ============================================ */
    // Chirpy의 post-nav wrapper 찾기
    var navWrapper = document.querySelector('.post-navigation')
      || document.querySelector('nav.post-navigation')
      || document.querySelector('.post-tail-wrapper .row');

    // .post-tail-wrapper 안의 btn들이 post-nav인 경우
    var tailWrapper = document.querySelector('.post-tail-wrapper');

    if (tailWrapper) {
      // .post-tail-wrapper 안의 모든 직계 링크/버튼 찾기
      var navBtns = tailWrapper.querySelectorAll(':scope > a, :scope > .btn, :scope > div > a, :scope > div > .btn');

      // row가 있으면 row를 flex로 변환
      var row = tailWrapper.querySelector('.row');
      if (row) {
        row.style.cssText = 'display:flex!important;flex-direction:' + (isMobile ? 'column' : 'row') + '!important;gap:0.75rem!important;width:100%!important;flex-wrap:nowrap!important;';
        // row 안의 col들
        row.querySelectorAll('[class*="col"]').forEach(function(col) {
          if (isMobile) {
            col.style.cssText = 'flex:1 1 100%!important;max-width:100%!important;width:100%!important;padding:0!important;';
          } else {
            col.style.cssText = 'flex:0 0 calc(50% - 0.375rem)!important;max-width:calc(50% - 0.375rem)!important;padding:0!important;';
          }
        });
        // col 안의 btn들
        row.querySelectorAll('.btn, a').forEach(function(btn) {
          btn.style.cssText += 'width:100%!important;max-width:100%!important;display:flex!important;align-items:center!important;overflow:hidden!important;text-overflow:ellipsis!important;white-space:nowrap!important;';
        });
      }
    }

    // 일반 .post-navigation도 처리
    if (navWrapper && navWrapper !== tailWrapper) {
      navWrapper.style.cssText = 'display:flex!important;flex-direction:' + (isMobile ? 'column' : 'row') + '!important;gap:0.75rem!important;width:100%!important;flex-wrap:nowrap!important;';
      navWrapper.querySelectorAll(':scope > a, :scope > div').forEach(function(child) {
        if (isMobile) {
          child.style.cssText += 'flex:1 1 100%!important;max-width:100%!important;width:100%!important;overflow:hidden!important;';
        } else {
          child.style.cssText += 'flex:0 0 calc(50% - 0.375rem)!important;max-width:calc(50% - 0.375rem)!important;overflow:hidden!important;';
        }
      });
    }

  });
})();
