using Application.Abstracts.Repositories;
using Application.Dtos.DistrictDtos;
using FluentValidation;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Application.Validations.DistrictValidation;

public class UpdateDistrictValidator: AbstractValidator<UpdateDistrictRequest>
{
    public UpdateDistrictValidator(IDistrictRepository districtRepository)
    {
         RuleFor(x => x.Name)
        .NotEmpty()
        .MaximumLength(100)
        .MustAsync(async (dto, name, ct) =>
            !await districtRepository.ExistsByNameDistrictAsync(name, dto.Id, ct))
        .WithMessage("This district name already exists.");
    }
}
