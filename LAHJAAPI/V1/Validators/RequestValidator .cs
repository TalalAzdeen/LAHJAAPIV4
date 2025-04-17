//using AutoGenerator.Conditions;
//using LAHJAAPI.Models;
//using LAHJAAPI.V1.Validators.Conditions;
//using Microsoft.AspNetCore.Mvc;

//using System;
//using TEP.Helper.Extensions;
//using Utilities;
//using V1.DyModels.Dso.Requests;
//using V1.DyModels.Dso.Responses;

//namespace LAHJAAPI.V1.Validators
//{



//    //public enum ApplicationUserValidatorStates
//    //{
//    //    IsActive,
//    //    IsFull,
//    //    HasCustomerId,
//    //    HasFirstName,
//    //    HasLastName,
//    //    HasDisplayName,
//    //    HasProfileUrl,
//    //    HasImageUrl,
//    //    HasLastLoginIp,
//    //    HasCreatedAt,
//    //    HasUpdatedAt,
//    //    IsNotArchived,
//    //    HasArchivedDate,
//    //    HasLastLoginDate


//    //}
//    public enum RequestValidatorStates
//    {
//        HasValidStatus,

//        HasQuestion,
//        IsAactiveSeesion,
//        IsValidRequestId,
//        IsFullAndError,
//        IsSubscriptionId,
//        IsAactiveAndAllowedRequest,
//        IsAactive,
//        IsAllowedRequest,
//        IsServiceId,
//        IsSpaceId,
//        IsUserId,
//        IsFull,
//        HasValidDate,
//        HasServiceIdIfNeeded,
//        HasSubscriptionIdIfNeeded,
//    }

//    public class RequestValidator : BaseValidator<RequestRequestDso, RequestValidatorStates>, ITValidator
//    {
//        private readonly IConditionChecker _checker;

//        public RequestValidator(IConditionChecker checker) : base(checker)
//        {
//            _checker = checker;
//        }


//        protected override void InitializeConditions()
//        {


//            _provider.Register(
//                RequestValidatorStates.HasValidStatus,
//                new LambdaCondition<RequestResponseDso>(
//                    nameof(RequestValidatorStates.HasValidStatus),
//                    context => !string.IsNullOrWhiteSpace(context.Status),
//                    "Status is required"
//                )
//            );

//            _provider.Register(
//                RequestValidatorStates.HasQuestion,
//                new LambdaCondition<RequestResponseDso>(
//                    nameof(RequestValidatorStates.HasQuestion),
//                    context => !string.IsNullOrWhiteSpace(context.Question),
//                    "Question is required"
//                )
//            );

//            //_provider.Register(
//            //    RequestValidatorStates.IsUserId,
//            //    new LambdaCondition<RequestRequestDso>(
//            //        nameof(RequestValidatorStates.IsUserId),
//            //        context => !string.IsNullOrWhiteSpace(context.UserId),
//            //        "User ID is required"
//            //    )
//            //);


//            //_provider.Register(
//            //     RequestValidatorStates.IsUserId,
//            //     new LambdaCondition<string>(
//            //         nameof(RequestValidatorStates.IsUserId),
//            //         context => !string.IsNullOrWhiteSpace(context),
//            //         "User ID is required"
//            //     )
//            // );



//            _provider.Register(
//                 RequestValidatorStates.IsFull,
//                 new LambdaCondition<RequestRequestDso>(
//                     nameof(RequestValidatorStates.IsFull),
//                     context => IsFullRresult(context),
//                     "Request is not"
//                 )
//             );
//            _provider.Register(
//               RequestValidatorStates.IsFullAndError,
//               new LambdaCondition<RequestRequestDso>(
//                   nameof(RequestValidatorStates.IsFullAndError),
//                   context => IsFullAndErorr(context),
//                   "Request is not"
//               )
//           );


//            _provider.Register(
//                    RequestValidatorStates.HasValidDate,
//                    new LambdaCondition<RequestResponseDso>(
//                        nameof(RequestValidatorStates.HasValidDate),
//                        context => context.CreatedAt <= context.UpdatedAt,
//                        "CreatedAt must be less than or equal to UpdatedAt"
//                    )
//                );

//            //_provider.Register(
//            //    RequestValidatorStates.HasServiceIdIfNeeded,
//            //    new LambdaCondition<RequestRequestDso>(
//            //        nameof(RequestValidatorStates.HasServiceIdIfNeeded),
//            //        context => !string.IsNullOrWhiteSpace(context.ServiceId),
//            //        "Service ID is required if not global"
//            //    )
//            //);

//            //_provider.Register(
//            //    RequestValidatorStates.HasSubscriptionIdIfNeeded,
//            //    new LambdaCondition<RequestRequestDso>(
//            //        nameof(RequestValidatorStates.HasSubscriptionIdIfNeeded),
//            //        context => !string.IsNullOrWhiteSpace(context.SubscriptionId),
//            //        "Subscription ID is required if not global"
//            //    )
//            //    );

//            _provider.Register(
//                RequestValidatorStates.IsAllowedRequest,
//                new LambdaCondition<RequestRequestDso>(
//                    nameof(RequestValidatorStates.IsAllowedRequest),
//                    context => IsAllowedRequest(context.ServiceId),
//                    "Service ID is required"
//                )
//            );

//            _provider.Register(
//                   RequestValidatorStates.IsValidRequestId,
//                   new LambdaCondition<RequestResponseDso>(
//                       nameof(RequestValidatorStates.IsValidRequestId),
//                       context => IsValidRequestId(context.Id),
//                       "Request ID is required"
//                   )
//               );

//            _provider.Register(
//                    RequestValidatorStates.IsValidRequestId,
//                    new LambdaCondition<string>(
//                        nameof(RequestValidatorStates.IsValidRequestId),
//                        context => IsValidRequestId(context),
//                        "Request ID is required"
//                    )
//                );
//            _provider.Register(
//                   RequestValidatorStates.IsSubscriptionId,
//                   new LambdaCondition<string>(
//                       nameof(RequestValidatorStates.IsSubscriptionId),
//                       context => IsValidSubscriptionId(context),
//                       "IsSubscriptionId  NotFound"
//                   )
//               );


//            _provider.Register(
//                 RequestValidatorStates.IsAactive,
//                 new LambdaCondition<RequestRequestDso>(
//                     nameof(RequestValidatorStates.IsAactive),
//                     context => IsValidAactiveAndAllowedRequest(context),
//                     "IsSubscriptionId  NotFound"
//                 )
//             );
//        }


//        //private bool IsValidCustomerId(string userId)
//        //{

//        //    return _checker.Check(RequestValidatorStates.IsUserId, userId);
//        //}


//        private async Task<bool>IsValidAactive(string subId)
//        {
//            //var result = await _checker.CheckAsync(
//            //    SubscriptionValidatorStates.IsActive, subId);

//            return true;

//        }
//        //private async Task<ConditionResult> IsValidAactiveResult(string subId)
//        //{
//        //    var result = await _checker.CheckAndResultAsync(
//        //        SubscriptionValidatorStates.IsActive, subId);

//        //   if((bool)result.Success)
//        //    {
//        //        var item =  IsValidAllowedRequest(subId);
//        //        if (item)
//        //        {
//        //            return new ConditionResult(true, true, "Active and AllowedRequest sussfule");
//        //        }
//        //        else
//        //        {
//        //            return new ConditionResult(true, false, "You have exhausted all allowed subscription requests");
//        //        }

//        //    }
//        //     return new ConditionResult(true, true,"111");

//        //}
//        private async Task<ConditionResult> ValidAactiveResult(string subId)
//        {
//            var result = await _checker.CheckAndResultAsync(SubscriptionValidatorStates.IsActive, subId);

//            if (result.Success is true)
//            {

//                if (IsAllowedRequest(subId))
//                {
//                    return new ConditionResult(true, null, "Subscription is active and allowed.");
//                }
//                else
//                {
//                    return new ConditionResult(false, new ProblemDetails
//                    {
//                        Title = "Create space",
//                        Detail = "You have exhausted all allowed subscription requests",
//                        Status = 602

//                    }
//                     );
//                }


//            }


//            return new ConditionResult(false, new ProblemDetails
//            {
//                Title = "Create space",
//                Detail = "No Ative ",
//                Status = 603

//            }
//                       );


//        }


//        private async Task<ConditionResult> IsValidAactiveAndAllowedRequest(RequestRequestDso context)
//        {



//            if (!await _checker.CheckAsync(SubscriptionValidatorStates.IsActive, "sub_1QwS2oKMQ7LabgRTjQMryYZ1"))

//                return new ConditionResult(false, new ProblemDetails
//                {
//                    Title = "Create Request",
//                    Detail = "No Ative ",
//                    Status = 603

//                });


//            if (IsAllowedRequest(context.SubscriptionId))


//                return new ConditionResult(true, null, "succful");


//            return new ConditionResult(false, new ProblemDetails
//            {
//                Title = "Request",
//                Detail = "You have exhausted all allowed subscription Request",
//                Status = 602

//            });










//        }





//        private bool IsAllowedRequest(string servid)
//        {


//            //var spaces = _checker.Injector.Context.Set<Space>()
//            //    .Where(x => x.SubscriptionId == subId)
//            //    .ToList();

//            var result = _checker.Injector.Context.Set<Subscription>()
//               .Any(sub => sub.AllowedSpaces < 70);

//            return result;
//        }

//        private async Task<bool> IsValidSubscriptionId(string subId)
//        {


//               var  result=await  _checker.CheckAsync(
//                  SubscriptionValidatorStates.IsActive, subId);

//                return result;


//        }

//        private bool IsValidSpace(string spacId)
//        {
//            return true;
//        }




//        private bool IsFull(RequestRequestDso? context)
//        {


//            var result1 = _checker.Check(
//                SpaceValidatorStates.IsSpaceId,
//                context.SpaceId);

//            var result2 = _checker.Check(
//                ServiceValidatorStates.IsServiceId,
//                context.ServiceId);

//            if (result1 == true && result2 == true)
//                return true;
//            return false;


//        }

//        private async Task<ConditionResult> IsFullRresult(RequestRequestDso? context)
//        {


//            var result1 =await _checker.CheckAndResultAsync(
//                SpaceValidatorStates.IsSpaceId,
//                context.SpaceId);

//            var result2 = await _checker.CheckAndResultAsync(
//                ServiceValidatorStates.IsServiceId,
//                context.ServiceId);


//            return new ConditionResult(true, new List<ConditionResult>() { result1, result2 }, "");

//            //if (result1 == true && result2 == true)
//            //    return true;
//            //return false;


//        }





//        private async Task<bool> ValidAactiveSeesion(string idsee)
//        {
//            return true;
//        }




//        private async Task<ConditionResult> IsFullAndErorr(RequestRequestDso? context)
//        {




//            if(!await _checker.CheckAsync(SpaceValidatorStates.IsSpaceId, context.SpaceId))

//                return new ConditionResult(false, new ProblemDetails
//                {
//                    Title = "Create Request",
//                    Detail = "This session has removed ",
//                    Status = 603

//                });


//            if(!await ValidAactiveSeesion(context.ServiceId))


//                return new ConditionResult(false, new ProblemDetails
//                {
//                    Title = "Create Request",
//                    Detail = $"This Service id {context.ServiceId} not in Service.",
//                    Status = 603

//                });



//             var service = await _checker.CheckAndResultAsync(ServiceValidatorStates.IsIsServiceIdAndResult, context.ServiceId);
//             if (service.Success is true)
//                {
//                    var objservice = (Service)service.Result;
//                    var modelAi = objservice.ModelAi;
//                    var modelGateway = modelAi.ModelGateway;
//                    context.Status = "Pending";
//                    context.ModelGateway = modelGateway.Url;
//                    context.ModelAi = modelAi.AbsolutePath;
//                    context.UserId ="7e6cd0a3-988b-4067-b224-40f4a8337671";
//                    context.ServiceId = objservice.Id;
//                    context.SubscriptionId = "sub_1QzOTHKMQ7LabgRTjEYXjnw1";
//                    return new ConditionResult(true, context, "susssc");

//             }
//                else
//                {
//                    return new ConditionResult(false, new ProblemDetails
//                    {
//                        Title = "Create space",
//                        Detail = "This service not found",
//                        Status = 603

//                    });

//                }











//            }




//            //if (result1 == true && result2 == true)
//            //    return true;
//            //return false;




//        private bool IsValidRequestId(string requestId)
//        {
//            if (requestId != "")
//            {
//                var result = _checker.Injector.Context.Set<Request>()
//                    .Any(x => x.Id == requestId);

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
using LAHJAAPI.Models;
using LAHJAAPI.V1.Validators.Conditions;
using V1.DyModels.Dso.Requests;
using V1.DyModels.Dso.Responses;

namespace LAHJAAPI.V1.Validators
{



    //public enum ApplicationUserValidatorStates
    //{
    //    IsActive,
    //    IsFull,
    //    HasCustomerId,
    //    HasFirstName,
    //    HasLastName,
    //    HasDisplayName,
    //    HasProfileUrl,
    //    HasImageUrl,
    //    HasLastLoginIp,
    //    HasCreatedAt,
    //    HasUpdatedAt,
    //    IsNotArchived,
    //    HasArchivedDate,
    //    HasLastLoginDate


    //}
    public enum RequestValidatorStates
    {
        HasValidStatus,

        HasQuestion,
        IsValidRequestId,

        IsAllowedRequest,
        IsServiceId,
        IsSpaceId,
        IsUserId,
        IsFull,
        HasValidDate,
        HasServiceIdIfNeeded,
        HasSubscriptionIdIfNeeded,
    }

    public class RequestValidator : BaseValidator<RequestRequestDso, RequestValidatorStates>, ITValidator
    {
        private readonly IConditionChecker _checker;

        public RequestValidator(IConditionChecker checker) : base(checker)
        {
            _checker = checker;
        }


        protected override void InitializeConditions()
        {




            _provider.Register(
                RequestValidatorStates.HasValidStatus,
                new LambdaCondition<RequestResponseDso>(
                    nameof(RequestValidatorStates.HasValidStatus),
                    context => !string.IsNullOrWhiteSpace(context.Status),
                    "Status is required"
                )
            );

            _provider.Register(
                RequestValidatorStates.HasQuestion,
                new LambdaCondition<RequestResponseDso>(
                    nameof(RequestValidatorStates.HasQuestion),
                    context => !string.IsNullOrWhiteSpace(context.Question),
                    "Question is required"
                )
            );

            //_provider.Register(
            //    RequestValidatorStates.IsUserId,
            //    new LambdaCondition<RequestRequestDso>(
            //        nameof(RequestValidatorStates.IsUserId),
            //        context => !string.IsNullOrWhiteSpace(context.UserId),
            //        "User ID is required"
            //    )
            //);


            //_provider.Register(
            //     RequestValidatorStates.IsUserId,
            //     new LambdaCondition<string>(
            //         nameof(RequestValidatorStates.IsUserId),
            //         context => !string.IsNullOrWhiteSpace(context),
            //         "User ID is required"
            //     )
            // );



            _provider.Register(
                 RequestValidatorStates.IsFull,
                 new LambdaCondition<RequestRequestDso>(
                     nameof(RequestValidatorStates.IsFull),
                     context => IsFull(context),
                     "Request is not"
                 )
             );



            _provider.Register(
                    RequestValidatorStates.HasValidDate,
                    new LambdaCondition<RequestResponseDso>(
                        nameof(RequestValidatorStates.HasValidDate),
                        context => context.CreatedAt <= context.UpdatedAt,
                        "CreatedAt must be less than or equal to UpdatedAt"
                    )
                );

            //_provider.Register(
            //    RequestValidatorStates.HasServiceIdIfNeeded,
            //    new LambdaCondition<RequestRequestDso>(
            //        nameof(RequestValidatorStates.HasServiceIdIfNeeded),
            //        context => !string.IsNullOrWhiteSpace(context.ServiceId),
            //        "Service ID is required if not global"
            //    )
            //);

            //_provider.Register(
            //    RequestValidatorStates.HasSubscriptionIdIfNeeded,
            //    new LambdaCondition<RequestRequestDso>(
            //        nameof(RequestValidatorStates.HasSubscriptionIdIfNeeded),
            //        context => !string.IsNullOrWhiteSpace(context.SubscriptionId),
            //        "Subscription ID is required if not global"
            //    )
            //    );

            _provider.Register(
                RequestValidatorStates.IsAllowedRequest,
                new LambdaCondition<RequestRequestDso>(
                    nameof(RequestValidatorStates.IsAllowedRequest),
                    context => IsValidAllowedRequest(context.ServiceId),
                    "Service ID is required"
                )
            );

            _provider.Register(
                   RequestValidatorStates.IsValidRequestId,
                   new LambdaCondition<RequestResponseDso>(
                       nameof(RequestValidatorStates.IsValidRequestId),
                       context => IsValidRequestId(context.Id),
                       "Request ID is required"
                   )
               );

            _provider.Register(
                    RequestValidatorStates.IsValidRequestId,
                    new LambdaCondition<string>(
                        nameof(RequestValidatorStates.IsValidRequestId),
                        context => IsValidRequestId(context),
                        "Request ID is required"
                    )
                );

        }


        //private bool IsValidCustomerId(string userId)
        //{

        //    return _checker.Check(RequestValidatorStates.IsUserId, userId);
        //}



        private bool IsValidAllowedRequest(string servid)
        {
            return true;
        }

        private bool IsValidSpace(string spacId)
        {
            return true;
        }




        private bool IsFull(RequestRequestDso? context)
        {

            var result1 = _checker.Check(
                SpaceValidatorStates.IsFound,
                context.SpaceId);

            var result2 = _checker.Check(
                ServiceValidatorStates.IsServiceIdFound,
                context.ServiceId);

            if (result1 == true && result2 == true)
                return true;
            return false;

            //return _checker.Check(
            //    SpaceValidatorStates.IsSpaceId,
            //    context.SpaceId
            //) && _checker.Check(
            //    ServiceValidatorStates.IsServiceId,
            //    context.ServiceId
            //);


            //&& 

            //_checker.Check(
            //    RequestValidatorStates.IsAllowedRequest,
            //    context.ServiceId
            //);
        }





        private bool IsValidRequestId(string requestId)
        {
            if (requestId != "")
            {
                var result = _checker.Injector.Context.Set<Request>()
                    .Any(x => x.Id == requestId);

                return result;
            }
            else
            {
                return false;

            }



        }
    }
}