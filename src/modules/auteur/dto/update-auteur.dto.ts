import { PartialType } from '@nestjs/mapped-types';
import { CreateAuteurDto } from './create-auteur.dto';

export class UpdateAuteurDto extends PartialType(CreateAuteurDto) {}
