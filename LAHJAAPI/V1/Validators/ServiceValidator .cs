//using AutoGenerator.Conditions;
//using LAHJAAPI.Models;
//using LAHJAAPI.V1.Validators.Conditions;
//using Microsoft.AspNetCore.Mvc;
//using Microsoft.EntityFrameworkCore;
//using V1.DyModels.Dso.Requests;

//namespace LAHJAAPI.V1.Validators
//{




//    public enum ServiceValidatorStates
//    {
//        IsFull,
//        IsServiceId,
//        IsIsServiceIdAndResult,
//        HasName,
//        HasAbsolutePath,
//        HasToken,
//        HasValidModelAi,
//        HasMethods,
//        HasRequests,
//        IsLinkedToUsers
//    }

//    public class ServiceValidator : BaseValidator<ServiceRequestDso, ServiceValidatorStates>, ITValidator
//    {
//        private readonly IConditionChecker _checker;

//        public ServiceValidator(IConditionChecker checker) : base(checker)
//        {
//            _checker = checker;
//        }

//        protected override void InitializeConditions()
//        {



//            _provider.Register(ServiceValidatorStates.IsIsServiceIdAndResult,
//              new LambdaCondition<string>(
//                  nameof(ServiceValidatorStates.IsIsServiceIdAndResult),
//                  context => VaildIsServiceIdResultAsync(context),
//                  "Service name is required"
//              )
//          );



//            _provider.Register(ServiceValidatorStates.HasName,
//                new LambdaCondition<ServiceRequestDso>(
//                    nameof(ServiceValidatorStates.HasName),
//                    s => !string.IsNullOrWhiteSpace(s.Name),
//                    "Service name is required"
//                )
//            );


//            _provider.Register(ServiceValidatorStates.HasAbsolutePath,
//                new LambdaCondition<ServiceRequestDso>(
//                    nameof(ServiceValidatorStates.HasAbsolutePath),
//                    s => Uri.IsWellFormedUriString(s.AbsolutePath, UriKind.Absolute),
//                    "AbsolutePath must be a valid URL"
//                )
//            );


//            _provider.Register(ServiceValidatorStates.HasToken,
//                new LambdaCondition<ServiceRequestDso>(
//                    nameof(ServiceValidatorStates.HasToken),
//                    s => !string.IsNullOrWhiteSpace(s.Token) && s.Token.Length >= 10,
//                    "Token is required and must be at least 10 characters"
//                )
//            );


//            _provider.Register(ServiceValidatorStates.HasValidModelAi,
//                new LambdaCondition<ServiceRequestDso>(
//                    nameof(ServiceValidatorStates.HasValidModelAi),
//                    s => string.IsNullOrWhiteSpace(s.ModelAiId) || s.ModelAi != null,
//                    "Model AI reference is invalid"
//                )
//            );



//            _provider.Register(ServiceValidatorStates.HasMethods,
//                new LambdaCondition<ServiceRequestDso>(
//                    nameof(ServiceValidatorStates.HasMethods),
//                    s => s.ServiceMethods != null && s.ServiceMethods.Any(),
//                    "Service must have at least one method"
//                )
//            );

//            _provider.Register(ServiceValidatorStates.HasRequests,
//                new LambdaCondition<ServiceRequestDso>(
//                    nameof(ServiceValidatorStates.HasRequests),
//                    s => s.Requests != null && s.Requests.Any(),
//                    "Service must have at least one request"
//                )
//            );

//            _provider.Register(ServiceValidatorStates.IsLinkedToUsers,
//                new LambdaCondition<ServiceRequestDso>(
//                    nameof(ServiceValidatorStates.IsLinkedToUsers),
//                    s => s.UserServices != null && s.UserServices.Any(),
//                    "Service must be linked to at least one user"
//                )
//            );
//            _provider.Register(ServiceValidatorStates.IsServiceId,
//                new LambdaCondition<string>(
//                    nameof(ServiceValidatorStates.IsServiceId),
//                    context => IsIdService(context),
//                    "Service ID is required"
//                )
//            );


//            //_provider.Where(
//            //    ServiceValidatorStates.IsFull,
//            //    new LambdaCondition<ServiceRequestDso>(
//            //        nameof(ServiceValidatorStates.IsFull),
//            //         ,
//            //        "Service is not full"
//            //    )
//            //);


//        }





//        private async Task<ConditionResult> VaildIsServiceIdResultAsync(string idServ)
//        {

//            var service = await _checker.Injector.Context.Services
//                      .Include(s => s.ModelAi)
//                      .ThenInclude(ai => ai.ModelGateway)
//                      .FirstOrDefaultAsync(s => s.Id == idServ);


//            if (service==null)

//                return new ConditionResult(false, null, "");

//          return new ConditionResult(true,service, "sussfule");


//        }


//        bool IsIdService(string idServ)
//        {



//            if (idServ != "")
//            {
//                var result = _checker.Injector.Context.Set<Service>()
//                    .Any(x => x.Id == idServ);

//                return result;
//            }
//            else
//            {
//                return false;

//            }
//        }

//    }
//}

using AutoGenerator.Conditions;
using LAHJAAPI.V1.Validators.Conditions;
using Microsoft.EntityFrameworkCore;
using V1.DyModels.Dso.Requests;

namespace LAHJAAPI.V1.Validators
{




    public enum ServiceValidatorStates
    {
        IsFull,
        IsServiceIdFound,
        IsServiceIdsEmpty,
        HasName,
        HasAbsolutePath,
        HasToken,
        HasValidModelAi,
        HasMethods,
        HasRequests,
        IsLinkedToUsers,
        IsServiceIdAndResult,
        IsAllowedServiceUser
    }

    public class ServiceValidator : BaseValidator<ServiceRequestDso, ServiceValidatorStates>, ITValidator
    {
        private readonly IConditionChecker _checker;

        public ServiceValidator(IConditionChecker checker) : base(checker)
        {
            _checker = checker;
        }

        protected override void InitializeConditions()
        {
            _provider.Register(ServiceValidatorStates.HasName,
                new LambdaCondition<ServiceRequestDso>(
                    nameof(ServiceValidatorStates.HasName),
                    s => !string.IsNullOrWhiteSpace(s.Name),
                    "Service name is required"
                )
            );

            _provider.Register(ServiceValidatorStates.HasAbsolutePath,
                new LambdaCondition<ServiceRequestDso>(
                    nameof(ServiceValidatorStates.HasAbsolutePath),
                    s => Uri.IsWellFormedUriString(s.AbsolutePath, UriKind.Absolute),
                    "AbsolutePath must be a valid URL"
                )
            );

            _provider.Register(ServiceValidatorStates.HasToken,
                new LambdaCondition<ServiceRequestDso>(
                    nameof(ServiceValidatorStates.HasToken),
                    s => !string.IsNullOrWhiteSpace(s.Token) && s.Token.Length >= 10,
                    "Token is required and must be at least 10 characters"
                )
            );

            _provider.Register(ServiceValidatorStates.HasValidModelAi,
                new LambdaCondition<ServiceRequestDso>(
                    nameof(ServiceValidatorStates.HasValidModelAi),
                    s => string.IsNullOrWhiteSpace(s.ModelAiId) || s.ModelAi != null,
                    "Model AI reference is invalid"
                )
            );

            _provider.Register(ServiceValidatorStates.HasMethods,
                new LambdaCondition<ServiceRequestDso>(
                    nameof(ServiceValidatorStates.HasMethods),
                    s => s.ServiceMethods != null && s.ServiceMethods.Any(),
                    "Service must have at least one method"
                )
            );

            _provider.Register(ServiceValidatorStates.HasRequests,
                new LambdaCondition<ServiceRequestDso>(
                    nameof(ServiceValidatorStates.HasRequests),
                    s => s.Requests != null && s.Requests.Any(),
                    "Service must have at least one request"
                )
            );

            _provider.Register(ServiceValidatorStates.IsLinkedToUsers,
                new LambdaCondition<ServiceRequestDso>(
                    nameof(ServiceValidatorStates.IsLinkedToUsers),
                    s => s.UserServices != null && s.UserServices.Any(),
                    "Service must be linked to at least one user"
                )
            );
            _provider.Register(ServiceValidatorStates.IsServiceIdFound,
                new LambdaCondition<string>(
                    nameof(ServiceValidatorStates.IsServiceIdFound),
                    context => IsServiceIdFound(context),
                    "You coudn't create space with this session. You need to create session with service create space."
                )
            );

            _provider.Register(ServiceValidatorStates.IsServiceIdsEmpty,
                new LambdaCondition<bool>(
                    nameof(ServiceValidatorStates.IsServiceIdsEmpty),
                    context => IsServiceIdsEmpty(context),
                    "Service Ids is empty."
                )
            );



            _provider.Register(ServiceValidatorStates.IsServiceIdAndResult,
              new LambdaCondition<string>(
                  nameof(ServiceValidatorStates.IsServiceIdAndResult),
                  context => VaildIsServiceIdResultAsync(context),
                  "Service name is required"
              )
          );
            _provider.Register(ServiceValidatorStates.IsAllowedServiceUser,
            new LambdaCondition<string>(
                nameof(ServiceValidatorStates.IsAllowedServiceUser),
                context => IsAllowedServiceUser(context),
                "Service name is required"
            )
        );

            //_provider.Where(
            //    ServiceValidatorStates.IsFull,
            //    new LambdaCondition<ServiceRequestDso>(
            //        nameof(ServiceValidatorStates.IsFull),
            //         ,
            //        "Service is not full"
            //    )
            //);


        }
        bool IsServiceIdFound(string idServ)
        {
            if (!string.IsNullOrWhiteSpace(idServ))
            {
                var result = _checker.Injector.UserClaims.ServicesIds?.Any(x => x == idServ);
                return result ?? false;
            }
            return false;
        }

        bool IsServiceIdsEmpty(bool idServ)
        {
            return _checker.Injector.UserClaims.ServicesIds?.Count == 0;
        }


        private async Task<ConditionResult> IsAllowedServiceUser(string idServ)
        {


            var result = _checker.Injector.Context.UserServices
                .Where(x => x.UserId == _checker.Injector.UserClaims.UserId && x.ServiceId == idServ);

            if (result != null)
            {

               return new ConditionResult(true, result, "sussfule");

            }
            return new ConditionResult(false, null, "error");
        }

        private async Task<ConditionResult> VaildIsServiceIdResultAsync(string idServ)
        {

            var service = await _checker.Injector.Context.Services
                      .Include(s => s.ModelAi)
                     .ThenInclude(ai => ai.ModelGateway)
                     .FirstOrDefaultAsync(s => s.Id == idServ);


            if (service == null)

                return new ConditionResult(false, null, "");

            return new ConditionResult(true, service, "sussfule");


        }















        //        private async Task<ConditionResult> VaildIsServiceIdResultAsync(string idServ)
        //        {

        //            var service = await _checker.Injector.Context.Services
        //                      .Include(s => s.ModelAi)
        //                      .ThenInclude(ai => ai.ModelGateway)
        //                      .FirstOrDefaultAsync(s => s.Id == idServ);


        //            if (service==null)

        //                return new ConditionResult(false, null, "");

        //          return new ConditionResult(true,service, "sussfule");


        //        }
        //bool IsServiceIdFound(string idServ)
        //{
        //    if (!String.IsNullOrWhiteSpace(idServ))
        //    {
        //        var result = _checker.Injector.Context.Set<Service>()
        //            .Any(x => x.Id == idServ);

        //        return result;
        //    }
        //    else
        //    {
        //        return false;

        //    }
        //}

    }
}