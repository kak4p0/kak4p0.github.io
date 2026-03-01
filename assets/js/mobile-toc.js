/**
 * kak4p0 Mobile Enhancements
 * 1) 인라인 TOC: 글 본문에 진짜 목차 생성 (모바일에서만)
 * 2) 사이드바 닫기: mask 탭하면 사이드바 닫힘
 * 
 * 설치: assets/js/mobile-toc.js 에 저장
 */
(function() {
  'use strict';

  document.addEventListener('DOMContentLoaded', function() {

    /* ============================================
       1) 모바일 인라인 TOC
       ============================================ */
    if (window.innerWidth < 992) {
      var postContent = document.querySelector('.post-content');
      if (postContent) {
        var headings = postContent.querySelectorAll('h2, h3, h4');
        if (headings.length >= 2) {
          // 각 헤딩에 id 없으면 자동 부여
          headings.forEach(function(h, i) {
            if (!h.id) h.id = 'heading-' + i;
          });

          // TOC HTML
          var html = '<details id="k-inline-toc"><summary>\uD83D\uDCD1 목차</summary><ul class="k-toc-list">';
          headings.forEach(function(h) {
            var level = h.tagName.toLowerCase();
            var text = h.textContent.replace(/#/g, '').trim();
            if (text) {
              html += '<li class="k-toc-' + level + '"><a href="#' + h.id + '">' + text + '</a></li>';
            }
          });
          html += '</ul></details>';
          postContent.insertAdjacentHTML('afterbegin', html);

          // 클릭 시 부드럽게 스크롤 (topbar 높이 보정)
          var toc = document.getElementById('k-inline-toc');
          if (toc) {
            toc.addEventListener('click', function(e) {
              var link = e.target.closest('a');
              if (!link) return;
              e.preventDefault();
              var target = document.getElementById(link.getAttribute('href').substring(1));
              if (!target) return;
              var topbarH = 52; // 3rem ≈ 48~52px
              try {
                topbarH = parseFloat(getComputedStyle(document.documentElement).getPropertyValue('--k-topbar-h')) * 16 || 52;
              } catch(ex) {}
              window.scrollTo({
                top: target.getBoundingClientRect().top + window.pageYOffset - topbarH - 12,
                behavior: 'smooth'
              });
            });
          }
        }
      }
    }

    /* ============================================
       2) 사이드바 mask 클릭으로 닫기 (백업)
       Chirpy JS가 정상이면 이미 동작하지만,
       혹시 안 될 때를 위한 보조 핸들러
       ============================================ */
    if (window.innerWidth < 992) {
      document.addEventListener('click', function(e) {
        var mask = document.getElementById('mask') || document.querySelector('.mask') || document.getElementById('sidebar-mask');
        if (!mask) return;
        if (e.target !== mask) return;

        // 사이드바 닫기: 다양한 Chirpy 버전 대응
        var sidebar = document.getElementById('sidebar');
        if (sidebar) {
          sidebar.classList.remove('active', 'show', 'sidebar-show');
          // Chirpy 7.x: transform 기반
          sidebar.style.transform = '';
        }

        // mask 숨기기
        mask.classList.remove('active', 'show', 'd-block');
        mask.style.display = 'none';
        mask.style.visibility = 'hidden';

        // body 클래스 정리
        document.body.classList.remove('sidebar-open', 'overflow-hidden');
        document.body.style.overflow = '';

        // Bootstrap offcanvas 정리 (Chirpy가 Bootstrap 쓸 경우)
        document.querySelectorAll('.offcanvas-backdrop').forEach(function(el) {
          el.remove();
        });
      });
    }

  });
})();
