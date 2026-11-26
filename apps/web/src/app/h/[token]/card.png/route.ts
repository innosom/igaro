import { cardProxy } from '../card-proxy';

export const dynamic = 'force-dynamic';

export function GET(req: Request, ctx: { params: Promise<{ token: string }> }): Promise<Response> {
  return cardProxy(req, ctx.params, 'png');
}
