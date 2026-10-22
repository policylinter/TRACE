import ts from 'typescript';
import fs from 'node:fs';
const names=['AccessPage','WorkspacesPage','AiSettingsPage','DevSecOpsPage'];
const extras={AccessPage:{JobRetentionPanel:'Хранение истории'},DevSecOpsPage:{SastJobsPanel:'Запуски SAST',SastRunnerHelp:'Подключение движка',SastResultsPanel:'Результаты SAST'}};
for(const name of names){
 const path=`src/pages/${name}.tsx`;let source=fs.readFileSync(path,'utf8');if(source.includes("from '@/components/SectionDeck'"))continue;
 const ast=ts.createSourceFile(path,source,ts.ScriptTarget.Latest,true,ts.ScriptKind.TSX);
 const fn=ast.statements.find(n=>ts.isFunctionDeclaration(n)&&n.name?.text===name);
 const returns=fn.body.statements.filter(ts.isReturnStatement);let root=returns.at(-1).expression;
 while(ts.isParenthesizedExpression(root))root=root.expression;
 if(!ts.isJsxElement(root))throw Error(name+' root');
 const changes=[];let count=0;
 function wrap(node,title){const id=name+'-'+(++count);changes.push([node.getStart(ast),`<DeckPanel id="${id}" title={${title}}>`],[node.end,'</DeckPanel>']);}
 function findTitle(node,tag){let found;function visit(n){if(found)return;if(ts.isJsxElement(n)&&n.openingElement.tagName.getText(ast)===tag){found=n;return;}ts.forEachChild(n,visit);}visit(node);return found;}
 function visit(node){
  if(ts.isJsxElement(node)){
   const tag=node.openingElement.tagName.getText(ast);
   if(['section','details'].includes(tag)){
    if(findTitle(node,'h1'))return;
    const heading=findTitle(node,tag==='details'?'summary':'h2');
    if(heading){const label=heading.children.map(c=>c.getText(ast)).join('').replace(/<span[\s\S]*?<\/span>/g,'');wrap(node,`<>${label}</>`);return;}
   }
  }
  if(ts.isJsxSelfClosingElement(node)){const label=extras[name]?.[node.tagName.getText(ast)];if(label){wrap(node,JSON.stringify(label));return;}}
  ts.forEachChild(node,visit);
 }
 root.children.forEach(visit);
 changes.push([root.openingElement.end,'<SectionDeck>'],[root.closingElement.getStart(ast),'</SectionDeck>']);
 changes.sort((a,b)=>b[0]-a[0]);for(const [at,text]of changes)source=source.slice(0,at)+text+source.slice(at);
 fs.writeFileSync(path,"import {SectionDeck,DeckPanel} from '@/components/SectionDeck';\n"+source);
 console.log(name,count,'sections');
}
