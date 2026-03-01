/**
 * kak4p0 Mobile Inline TOC
 * 모바일에서 글 본문에 진짜 목차를 자동 생성
 * 
 * 설치: assets/js/mobile-toc.js
 */
(function() {
  'use strict';

  document.addEventListener('DOMContentLoaded', function() {
    // 모바일에서만 실행
    if (window.innerWidth >= 992) return;

    // 포스트 페이지에서만
    var postContent = document.querySelector('.post-content');
    if (!postContent) return;

    // h2, h3, h4 수집
    var headings = postContent.querySelectorAll('h2, h3, h4');
    if (headings.length < 2) return;

    // id 부여
    headings.forEach(function(h, i) {
      if (!h.id) h.id = 'heading-' + i;
    });

    // TOC 생성
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

    // 스크롤 (topbar 높이 보정)
    var toc = document.getElementById('k-inline-toc');
    if (toc) {
      toc.addEventListener('click', function(e) {
        var link = e.target.closest('a');
        if (!link) return;
        e.preventDefault();
        var target = document.getElementById(link.getAttribute('href').substring(1));
        if (!target) return;
        var topbarH = 52;
        window.scrollTo({
          top: target.getBoundingClientRect().top + window.pageYOffset - topbarH - 12,
          behavior: 'smooth'
        });
      });
    }
  });
})();
