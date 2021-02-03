import {
  Arg,
  Ctx,
  Field,
  Int,
  Mutation,
  ObjectType,
  Query,
  Resolver,
  UseMiddleware,
} from 'type-graphql';
import { compare, hash } from 'bcryptjs';
import { User } from './entity/User';
import { AppContext } from './types';
import {
  createAccessToken,
  createRefreshToken,
  sendRefreshToken,
} from './utils/auth';
import { isAuth } from './middleware/is-auth';
import { getConnection } from 'typeorm';

@ObjectType()
class LoginResponse {
  @Field()
  accessToken: string;
}

@Resolver()
export class UserResolver {
  @Query(() => String)
  hello() {
    return 'Hi!';
  }

  @Query(() => String)
  @UseMiddleware(isAuth)
  sup(@Ctx() { payload }: AppContext) {
    console.log('> payload:', payload);
    return `Your user id is ${payload!.userId} 👋`;
  }

  @Query(() => [User])
  users() {
    return User.find();
  }

  @Mutation(() => Boolean)
  async revokeRefreshTokensForUser(@Arg('userId', () => Int) userId: number) {
    await getConnection()
      .getRepository(User)
      .increment({ id: userId }, 'tokenVersion', 1);
    return true;
  }

  @Mutation(() => LoginResponse)
  async login(
    @Arg('email') email: string,
    @Arg('password') password: string,
    @Ctx() { res }: AppContext,
  ): Promise<LoginResponse> {
    const user = await User.findOne({ where: { email } });
    if (!user) throw new Error('could not find user');

    const valid = await compare(password, user.password);
    if (!valid) throw new Error('invalid password');

    // logged in
    sendRefreshToken(res, createRefreshToken(user));
    return {
      accessToken: createAccessToken(user),
    };
  }

  @Mutation(() => Boolean)
  async register(
    @Arg('email') email: string,
    @Arg('password') password: string,
  ) {
    const hashedPassword = await hash(password, 12);
    try {
      await User.insert({
        email,
        password: hashedPassword,
      });
      return true;
    } catch (err) {
      console.log(err);
      return false;
    }
  }
}
