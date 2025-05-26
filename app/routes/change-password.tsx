import { type FieldValues, useForm } from "react-hook-form";
import {
  type ActionFunctionArgs,
  type LoaderFunctionArgs,
  type MetaFunction,
  redirect,
  useActionData,
  useSubmit,
} from "react-router";
import { Button } from "~/components/button";
import { Input } from "~/components/input";
import { checkAuth } from "~/lib/check-auth";
import { authCookie } from "~/lib/cookies.server";
import { prisma } from "~/lib/prisma.server";
import { badRequest } from "~/lib/responses";
import argon2 from "argon2";

export async function loader({ request }: LoaderFunctionArgs) {
  try {
    await checkAuth(request);
  } catch (error) {
    return redirect("/login");
  }
  return null;
}

export async function action({ request }: ActionFunctionArgs) {
  const { userId } =
    (await authCookie.parse(request.headers.get("Cookie"))) || {};
  if (!userId) {
    return redirect("/login");
  }

  const user = await prisma.user.findUnique({
    where: { id: userId },
  });

  if (!user) {
    return redirect("/login");
  }

  const formData = await request.json();
  const { currentPassword, newPassword } = formData;

  if (!currentPassword || !newPassword) {
    return badRequest({
      detail: "Current password and new password are required",
    });
  }

  if (newPassword.length < 8) {
    return badRequest({
      detail: "New password must be at least 8 characters long",
    });
  }

  const isPasswordValid = await argon2.verify(user.password, currentPassword);
  if (!isPasswordValid) {
    return badRequest({ detail: "Current password is incorrect" });
  }

  const hashedPassword = await argon2.hash(newPassword);
  await prisma.user.update({
    where: { id: user.id },
    data: { password: hashedPassword },
  });

  return redirect("/", {
    headers: {
      "Set-Cookie": await authCookie.serialize({ userId: user.id }),
    },
  });
}

export const meta: MetaFunction = () => {
  return [{ title: "Change Password" }];
};

export default function ChangePassword() {
  const actionData = useActionData<typeof action>();
  const { register, handleSubmit, watch } = useForm();
  const submit = useSubmit();

  const $newPassword = watch("newPassword")?.length || 0;

  function onSubmit(data: FieldValues) {
    submit(JSON.stringify(data), {
      method: "POST",
      encType: "application/json",
    });
  }

  return (
    <div className="flex h-screen w-screen items-center justify-center">
      <div className="w-74 rounded-lg border border-gray-200 bg-stone-50 dark:(bg-neutral-900 border-neutral-800) shadow-lg -mt-10rem">
        <div className="p-4">
          <h1 className="font-medium">Change Password</h1>
          <p className="text-sm text-gray-500 mb-2">
            Enter your current password and choose a new one.
          </p>
          {actionData?.detail && (
            <p className="text-sm text-rose-500 mb-2">{actionData.detail}</p>
          )}
          <form onSubmit={handleSubmit(onSubmit)} className="space-y-2">
            <Input
              type="password"
              placeholder="current password"
              className="font-mono"
              {...register("currentPassword", { required: true })}
            />

            <div className="relative">
              <Input
                type="password"
                placeholder="new password"
                className="font-mono pr-8"
                {...register("newPassword", {
                  required: "New password is required",
                  minLength: {
                    value: 8,
                    message: "Password must be at least 8 characters",
                  },
                })}
              />
              <span
                className={`
                  absolute right-2 top-1/2 -translate-y-1/2
                  w-2 h-2 rounded-full
                  ${
                    $newPassword >= 8
                      ? "bg-green-600"
                      : "dark:bg-neutral-700 bg-neutral-400"
                  }
                `}
                aria-hidden="true"
              />
            </div>

            <Button className="gap-1" type="submit">
              Change Password
              <div className="i-lucide-key" />
            </Button>
          </form>
        </div>

        <div className="border-t dark:border-neutral-800 bg-stone-200/40 dark:bg-neutral-800/30 px-4 py-2 flex justify-end">
          <a
            href="https://github.com/Akarikev/todo-list"
            className="flex items-center gap-1 bg-stone-200 dark:bg-neutral-800 px-2 py-1 rounded-xl text-secondary font-mono text-sm font-medium"
            target="_blank"
            rel="noreferrer"
          >
            <div className="i-lucide-github" /> todo-list
          </a>
        </div>
      </div>
    </div>
  );
}
