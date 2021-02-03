import 'dotenv/config';
import 'reflect-metadata';
import express from 'express';
import { ApolloServer } from 'apollo-server-express';
import { buildSchema } from 'type-graphql';
import { UserResolver } from './user-resolver';
import { createConnection } from 'typeorm';
import cookieParser from 'cookie-parser';
import { verify } from 'jsonwebtoken';
import { User } from './entity/User';
import {
  createAccessToken,
  createRefreshToken,
  sendRefreshToken,
} from './utils/auth';

const PORT = process.env.PORT || 4000;

(async () => {
  const app = express();
  app.use(cookieParser());

  app.post('/refresh_token', async (req, res) => {
    const token = req.cookies.uid;
    let payload: any;
    if (!token) {
      return res.send({ ok: false, accessToken: '' });
    }

    try {
      payload = verify(token, process.env.REFRESH_TOKEN_SECRET!);
    } catch (err) {
      console.log(err);
      return res.send({ ok: false, accessToken: '' });
    }

    // token is valid, send refresh token
    const user = await User.findOne({ id: payload.userId });

    if (!user) return res.send({ ok: false, accessToken: '' });
    if (user.tokenVersion !== payload.tokenVersion) {
      return res.send({ ok: false, accessToken: '' });
    }

    sendRefreshToken(res, createRefreshToken(user));
    return res.send({ ok: true, accessToken: createAccessToken(user) });
  });

  await createConnection();
  const apolloServer = new ApolloServer({
    schema: await buildSchema({
      resolvers: [UserResolver],
    }),
    context: ({ req, res }) => ({ req, res }),
  });
  apolloServer.applyMiddleware({ app });
  app.listen(PORT, () => console.log(`Server running on port ${PORT}...`));
})();
