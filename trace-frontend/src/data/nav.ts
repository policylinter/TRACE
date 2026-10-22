export type NavGroup = 'обзор' | 'анализ' | 'отчёты' | 'система';

export interface NavItem {
  id: 'monitoring' | 'governance' | 'cicd' | 'sast' | 'dast' | 'sca' | 'workspaces' | 'access' | 'platform' | 'scans' | 'projects' | 'overview' | 'findings' | 'reachability' | 'sbom' | 'vex' | 'advisory' | 'compliance' | 'settings';
  label: string;
  glyph: 'grid' | 'list' | 'graph' | 'layers' | 'doc' | 'shield' | 'cpu';
  badgeKey?: 'total' | 'reachable' | 'components' | 'vex';
}

export interface NavGroupDef {
  id: NavGroup;
  label: string;
  items: NavItem[];
}

export const NAV_GROUPS: NavGroupDef[] = [
  { id: 'обзор', label: 'Рабочее пространство', items: [
    {id:'overview',label:'Обзор',glyph:'grid'},
    {id:'projects',label:'Проекты',glyph:'layers'},
    {id:'platform',label:'Активы и модули',glyph:'cpu'},
    {id:'monitoring',label:'Мониторинг и инциденты',glyph:'shield'},
    {id:'governance',label:'Риски и задачи',glyph:'doc'},
  ]},
  { id: 'анализ', label: 'Безопасность разработки', items: [
    {id:'cicd',label:'CI/CD',glyph:'graph'},
    {id:'sast',label:'SAST',glyph:'doc'},
    {id:'dast',label:'DAST',glyph:'shield'},
    {id:'sca',label:'SCA',glyph:'layers'},
    {id:'findings',label:'Уязвимости',glyph:'list',badgeKey:'total'},
    {id:'scans',label:'Проверки',glyph:'graph'},
  ]},
  { id: 'отчёты', label: 'Аналитика и данные', items: [
    {id:'sbom',label:'Зависимости',glyph:'layers',badgeKey:'components'},
    {id:'vex',label:'Отчёты VEX',glyph:'doc'},
    {id:'compliance',label:'Соответствие стандартам',glyph:'shield'},
    {id:'advisory',label:'База уязвимостей',glyph:'list'},
  ]},
  { id: 'система', label: 'Администрирование', items: [
    {id:'workspaces',label:'Пространства и команды',glyph:'layers'},
    {id:'access',label:'Организация и доступ',glyph:'shield'},
    {id:'settings',label:'Настройки',glyph:'cpu'},
  ]},
];
export const NAV_ITEMS: NavItem[] = NAV_GROUPS.flatMap(group => group.items);
export function primaryNav(id: NavItem['id']): NavItem['id'] {
  return id === 'reachability' ? 'findings' : id;
}

export const KEYBOARD_NAV: NavItem['id'][] = ['overview','findings','sbom','scans','vex','advisory','settings'];
