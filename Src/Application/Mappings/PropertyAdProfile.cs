using Application.Dtos.PropertyAdDtos;
using AutoMapper;
using Domain.Entities;

namespace Application.Mappings;

public class PropertyAdProfile:Profile
{
    public PropertyAdProfile()
    {
        CreateMap<PropertyMedia, PropertyMediaItemDto>();

        CreateMap<PropertyAd, GetAllPropertyAdResponse>()
            .ForMember(d => d.FirstMediaUrl, o => o.MapFrom(s =>
                s.MediaItems!
                    .OrderBy(x => x.Order)
                    .Select(x => x.ObjectKey)
                    .FirstOrDefault()
            ));

        CreateMap<PropertyAd, GetByIdPropertyAdResponse>()
            .ForMember(d => d.Media, o => o.MapFrom(s =>
                s.MediaItems!.OrderBy(x => x.Order)
            ));
        CreateMap<CreatePropertyAdRequest, PropertyAd>();
        CreateMap<UpdatePropertyAdRequest, PropertyAd>()
            .ForAllMembers(opts => opts.Condition((src, dest, srcMember) => srcMember != null));
        CreateMap<PropertyMedia, PropertyMediaItemDto>();
    }
}
