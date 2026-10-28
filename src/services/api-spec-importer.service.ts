import { DiscoveredResource } from './crawler.service';

export interface ApiEndpointSpec {
  path: string;
  method: 'GET' | 'POST' | 'PUT' | 'DELETE' | 'PATCH' | 'OPTIONS' | 'HEAD';
  summary?: string;
  parameters: Array<{ name: string; in: 'query' | 'header' | 'path' | 'body'; required?: boolean; type?: string }>;
  requestBodySample?: any;
}

export class ApiSpecImporterService {
  /**
   * Parses OpenAPI 2.0 / 3.0 or Postman Collection JSON into structured DiscoveredResource items
   */
  public static parseSpec(specContent: string, baseUrl: string): { endpoints: ApiEndpointSpec[]; resources: DiscoveredResource[] } {
    const endpoints: ApiEndpointSpec[] = [];
    const resources: DiscoveredResource[] = [];

    try {
      const data = typeof specContent === 'string' ? JSON.parse(specContent) : specContent;

      // 1. OpenAPI / Swagger 2.0 or 3.0
      if (data.swagger || data.openapi || data.paths) {
        const paths = data.paths || {};
        for (const [pathKey, pathMethods] of Object.entries(paths)) {
          if (!pathMethods || typeof pathMethods !== 'object') continue;

          for (const [methodKey, methodObj] of Object.entries(pathMethods as Record<string, any>)) {
            const mUpper = methodKey.toUpperCase();
            if (!['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS', 'HEAD'].includes(mUpper)) continue;

            const params: any[] = [];
            if (Array.isArray(methodObj.parameters)) {
              for (const p of methodObj.parameters) {
                params.push({
                  name: p.name || 'param',
                  in: p.in || 'query',
                  required: Boolean(p.required),
                  type: p.schema?.type || p.type || 'string',
                });
              }
            }

            endpoints.push({
              path: pathKey,
              method: mUpper as any,
              summary: methodObj.summary || methodObj.description || `${mUpper} ${pathKey}`,
              parameters: params,
            });

            // Clean full URL
            const cleanBase = baseUrl.replace(/\/+$/, '');
            const cleanPath = pathKey.startsWith('/') ? pathKey : `/${pathKey}`;
            resources.push({
              url: `${cleanBase}${cleanPath}`,
              type: 'API_ENDPOINT',
              statusCode: 200,
              responseTimeMs: 15,
              status: 'REACHABLE',
            });
          }
        }
      }

      // 2. Postman Collection Format
      if (Array.isArray(data.item)) {
        function traversePostman(items: any[], prefix = '') {
          for (const item of items) {
            if (item.request) {
              const req = item.request;
              const method = (req.method || 'GET').toUpperCase();
              let rawUrl = '';
              if (typeof req.url === 'string') {
                rawUrl = req.url;
              } else if (req.url && req.url.raw) {
                rawUrl = req.url.raw;
              }

              const cleanUrl = rawUrl.startsWith('http') ? rawUrl : `${baseUrl.replace(/\/+$/, '')}/${rawUrl.replace(/^\/+/, '')}`;
              endpoints.push({
                path: rawUrl,
                method: method as any,
                summary: item.name || `${method} ${rawUrl}`,
                parameters: [],
              });

              resources.push({
                url: cleanUrl,
                type: 'API_ENDPOINT',
                statusCode: 200,
                responseTimeMs: 20,
                status: 'REACHABLE',
              });
            } else if (Array.isArray(item.item)) {
              traversePostman(item.item, `${prefix}/${item.name || ''}`);
            }
          }
        }

        traversePostman(data.item);
      }
    } catch (err) {
      console.warn('[ApiSpecImporter] Error parsing API spec:', (err as Error).message);
    }

    return { endpoints, resources };
  }
}
