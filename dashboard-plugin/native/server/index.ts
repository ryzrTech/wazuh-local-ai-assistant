import { PluginInitializerContext } from 'opensearch_dashboards/server';
import { LocalAiServerPlugin } from './plugin';

export function plugin(context: PluginInitializerContext) {
  return new LocalAiServerPlugin(context);
}
