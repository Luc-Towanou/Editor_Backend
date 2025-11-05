import { HttpException, HttpStatus } from '@nestjs/common';

export class UserNotFoundException extends HttpException {
  constructor(user_id?: string | null) {
    super(
      {
        statusCode: HttpStatus.NOT_FOUND,
        message: user_id
          ? `Utilisateur avec l'ID ${user_id} introuvable`
          : 'Utilisateur introuvable',
        error: 'User Not Found',
        timestamp: new Date().toISOString(),
      },
      HttpStatus.NOT_FOUND,
    );
  }
}
