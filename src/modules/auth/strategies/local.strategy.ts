import { Strategy } from 'passport-local';
import { PassportStrategy } from '@nestjs/passport';
import { Injectable, UnauthorizedException } from '@nestjs/common';
import { AuthService } from '../auth.service';

@Injectable()
export class LocalStrategy extends PassportStrategy(Strategy) {
  constructor(private authService: AuthService) {
    super({ usernameField: 'email', passwordField: 'mot_de_passe' });
  }

  async validate(email: string, mot_de_passe: string) {
    const user = await this.authService.validateUser(email, mot_de_passe);
    if (!user) {
      throw new UnauthorizedException('Email ou mot de passe invalide');
    }
    return user;
  }
}
