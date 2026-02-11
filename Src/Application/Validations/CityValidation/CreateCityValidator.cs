using Application.Abstracts.Repositories;
using Application.Dtos.CityDtos;
using FluentValidation;

namespace Application.Validations.CityValidation;

public class CreateCityValidator: AbstractValidator<CreateCityRequest>
{
    private readonly ICityRepository _cityRepository;

    public CreateCityValidator(ICityRepository cityRepository)
    {
        _cityRepository = cityRepository;
        RuleFor(x => x.Name)
                   .NotEmpty().WithMessage("City name cannot be empty.")
                   .MaximumLength(100).WithMessage("City name can be at most 100 characters long.")
                   .Matches("^[a-zA-ZğüşöçıİĞÜŞÖÇ ]+$").WithMessage("City name can only contain letters and spaces.")
                   .MustAsync(async (name, ct) =>
                       !await _cityRepository.ExistsByNameAsync(name.Trim(), 0, ct))
                   .WithMessage("City with this name already exists.");


    }
}
