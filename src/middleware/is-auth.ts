import { verify } from 'jsonwebtoken';
import { AppContext } from 'src/types';
import { MiddlewareFn } from 'type-graphql/dist/interfaces/Middleware';

export const isAuth: MiddlewareFn<AppContext> = ({ context }, next: any) => {
  const authorization = context.req.headers['authorization'];

  try {
    if (!authorization) throw new Error('Not authenticated');
    const [, token] = authorization?.split(' ');
    const payload = verify(token, process.env.ACCESS_TOKEN_SECRET!);
    context.payload = payload as any;
    return next();
  } catch (err) {
    console.log(err);
    throw new Error('Not authenticated');
  }
  return next();
};
