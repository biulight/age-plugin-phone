// @ts-check
const {themes} = require('prism-react-renderer');

/** @type {import('@docusaurus/types').Config} */
const config = {
  title: 'age-plugin-phone',
  tagline: 'Approve age decryption on your phone',
  url: 'https://biulight.github.io',
  baseUrl: '/age-plugin-phone/',
  organizationName: 'biulight',
  projectName: 'age-plugin-phone',
  trailingSlash: false,
  onBrokenLinks: 'throw',
  markdown: {hooks: {onBrokenMarkdownLinks: 'throw'}},
  i18n: {
    defaultLocale: 'en',
    locales: ['en', 'zh-Hans'],
    localeConfigs: {
      en: {label: 'English', htmlLang: 'en'},
      'zh-Hans': {label: '简体中文', htmlLang: 'zh-CN'},
    },
  },
  presets: [['classic', /** @type {import('@docusaurus/preset-classic').Options} */ ({
    docs: {
      path: '../docs/manual',
      routeBasePath: '/',
      sidebarPath: require.resolve('./sidebars.js'),
      editUrl: ({locale, docPath}) => {
        const root = locale === 'en' ? 'docs/manual'
          : 'website/i18n/zh-Hans/docusaurus-plugin-content-docs/current';
        return `https://github.com/biulight/age-plugin-phone/edit/main/${root}/${docPath}`;
      },
    },
    blog: false,
  })]],
  themeConfig: /** @type {import('@docusaurus/preset-classic').ThemeConfig} */ ({
    navbar: {
      title: 'age-plugin-phone',
      items: [
        {type: 'docSidebar', sidebarId: 'manual', label: 'Documentation', position: 'left'},
        {type: 'localeDropdown', position: 'right'},
        {href: 'https://github.com/biulight/age-plugin-phone', label: 'GitHub', position: 'right'},
      ],
    },
    footer: {
      style: 'dark',
      links: [{title: 'Project', items: [
        {label: 'Releases', href: 'https://github.com/biulight/age-plugin-phone/releases'},
        {label: 'Biulight', href: 'https://blog.biulight.top/timeline/products'},
      ]}],
    },
    prism: {theme: themes.github, darkTheme: themes.dracula, additionalLanguages: ['powershell', 'toml']},
  }),
};
module.exports = config;
