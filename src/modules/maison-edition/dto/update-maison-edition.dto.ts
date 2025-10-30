import { PartialType } from '@nestjs/mapped-types';
import { CreateMaisonEditionDto } from './create-maison-edition.dto';

export class UpdateMaisonEditionDto extends PartialType(CreateMaisonEditionDto) {}
