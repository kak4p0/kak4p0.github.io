/**
 * kak4p0 Mobile Inline TOC
 * 모바일에서 글 본문에 목차 자동 생성 (그 외 아무것도 건드리지 않음)
 */
(function() {
  'use strict';
  document.addEventListener('DOMContentLoaded', function() {
    if (window.innerWidth >= 992) return;
    var pc = document.querySelector('.post-content');
    if (!pc) return;
    var hh = pc.querySelectorAll('h2, h3, h4');
    if (hh.length < 2) return;
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
  });
})();
