import { IsEmail, IsNotEmpty, IsOptional, IsString, MinLength } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

export class SignupDto {
  @ApiProperty({
    example: 'John Doe',
    description: 'Nom complet de l’utilisateur',
  })
  @IsNotEmpty() nom: string;


  @ApiProperty({
    example: 'john@example.com',
    description: 'Adresse email unique de l’utilisateur',
  })
  @IsEmail() email: string;


  @ApiProperty({
    example: '@MotDePasse123!',
    description: 'Mot de passe sécurisé (min. 8 caractères)',
  })
  @MinLength(8)
  @IsNotEmpty() mot_de_passe: string;


  @ApiProperty({
    example: '0162897259',
    description: 'Numero de telephone (Benin. 10 caractères par defaut)',
    required: false, // 👈 indique à Swagger que ce champ est optionnel
  })
  @IsOptional() telephone?: string;


  @IsOptional() role?: string; // validate côté service
  @IsOptional() maison_id?: string; // invitation flow / création maison
  
}
