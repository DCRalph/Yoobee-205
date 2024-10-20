/* prettier-ignore-start */

/* eslint-disable */

// @ts-nocheck

// noinspection JSUnusedGlobalSymbols

// This file is auto-generated by TanStack Router

// Import Routes

import { Route as rootRoute } from './routes/__root'
import { Route as TestImport } from './routes/test'
import { Route as ScrapingOrdersImport } from './routes/scraping-orders'
import { Route as ScrapingOrderTargetImport } from './routes/scraping-order-target'
import { Route as ScrapingOrderImport } from './routes/scraping-order'
import { Route as RegisterImport } from './routes/register'
import { Route as PaymentPageImport } from './routes/payment-page'
import { Route as LoginImport } from './routes/login'
import { Route as ContactImport } from './routes/contact'
import { Route as AccountImport } from './routes/account'
import { Route as AboutImport } from './routes/about'
import { Route as IndexImport } from './routes/index'
import { Route as OrderDetailsOrderIdImport } from './routes/order-details.$orderId'
import { Route as CleanedDataOrderIdImport } from './routes/cleaned-data.$orderId'

// Create/Update Routes

const TestRoute = TestImport.update({
  path: '/test',
  getParentRoute: () => rootRoute,
} as any)

const ScrapingOrdersRoute = ScrapingOrdersImport.update({
  path: '/scraping-orders',
  getParentRoute: () => rootRoute,
} as any)

const ScrapingOrderTargetRoute = ScrapingOrderTargetImport.update({
  path: '/scraping-order-target',
  getParentRoute: () => rootRoute,
} as any)

const ScrapingOrderRoute = ScrapingOrderImport.update({
  path: '/scraping-order',
  getParentRoute: () => rootRoute,
} as any)

const RegisterRoute = RegisterImport.update({
  path: '/register',
  getParentRoute: () => rootRoute,
} as any)

const PaymentPageRoute = PaymentPageImport.update({
  path: '/payment-page',
  getParentRoute: () => rootRoute,
} as any)

const LoginRoute = LoginImport.update({
  path: '/login',
  getParentRoute: () => rootRoute,
} as any)

const ContactRoute = ContactImport.update({
  path: '/contact',
  getParentRoute: () => rootRoute,
} as any)

const AccountRoute = AccountImport.update({
  path: '/account',
  getParentRoute: () => rootRoute,
} as any)

const AboutRoute = AboutImport.update({
  path: '/about',
  getParentRoute: () => rootRoute,
} as any)

const IndexRoute = IndexImport.update({
  path: '/',
  getParentRoute: () => rootRoute,
} as any)

const OrderDetailsOrderIdRoute = OrderDetailsOrderIdImport.update({
  path: '/order-details/$orderId',
  getParentRoute: () => rootRoute,
} as any)

const CleanedDataOrderIdRoute = CleanedDataOrderIdImport.update({
  path: '/cleaned-data/$orderId',
  getParentRoute: () => rootRoute,
} as any)

// Populate the FileRoutesByPath interface

declare module '@tanstack/react-router' {
  interface FileRoutesByPath {
    '/': {
      id: '/'
      path: '/'
      fullPath: '/'
      preLoaderRoute: typeof IndexImport
      parentRoute: typeof rootRoute
    }
    '/about': {
      id: '/about'
      path: '/about'
      fullPath: '/about'
      preLoaderRoute: typeof AboutImport
      parentRoute: typeof rootRoute
    }
    '/account': {
      id: '/account'
      path: '/account'
      fullPath: '/account'
      preLoaderRoute: typeof AccountImport
      parentRoute: typeof rootRoute
    }
    '/contact': {
      id: '/contact'
      path: '/contact'
      fullPath: '/contact'
      preLoaderRoute: typeof ContactImport
      parentRoute: typeof rootRoute
    }
    '/login': {
      id: '/login'
      path: '/login'
      fullPath: '/login'
      preLoaderRoute: typeof LoginImport
      parentRoute: typeof rootRoute
    }
    '/payment-page': {
      id: '/payment-page'
      path: '/payment-page'
      fullPath: '/payment-page'
      preLoaderRoute: typeof PaymentPageImport
      parentRoute: typeof rootRoute
    }
    '/register': {
      id: '/register'
      path: '/register'
      fullPath: '/register'
      preLoaderRoute: typeof RegisterImport
      parentRoute: typeof rootRoute
    }
    '/scraping-order': {
      id: '/scraping-order'
      path: '/scraping-order'
      fullPath: '/scraping-order'
      preLoaderRoute: typeof ScrapingOrderImport
      parentRoute: typeof rootRoute
    }
    '/scraping-order-target': {
      id: '/scraping-order-target'
      path: '/scraping-order-target'
      fullPath: '/scraping-order-target'
      preLoaderRoute: typeof ScrapingOrderTargetImport
      parentRoute: typeof rootRoute
    }
    '/scraping-orders': {
      id: '/scraping-orders'
      path: '/scraping-orders'
      fullPath: '/scraping-orders'
      preLoaderRoute: typeof ScrapingOrdersImport
      parentRoute: typeof rootRoute
    }
    '/test': {
      id: '/test'
      path: '/test'
      fullPath: '/test'
      preLoaderRoute: typeof TestImport
      parentRoute: typeof rootRoute
    }
    '/cleaned-data/$orderId': {
      id: '/cleaned-data/$orderId'
      path: '/cleaned-data/$orderId'
      fullPath: '/cleaned-data/$orderId'
      preLoaderRoute: typeof CleanedDataOrderIdImport
      parentRoute: typeof rootRoute
    }
    '/order-details/$orderId': {
      id: '/order-details/$orderId'
      path: '/order-details/$orderId'
      fullPath: '/order-details/$orderId'
      preLoaderRoute: typeof OrderDetailsOrderIdImport
      parentRoute: typeof rootRoute
    }
  }
}

// Create and export the route tree

export interface FileRoutesByFullPath {
  '/': typeof IndexRoute
  '/about': typeof AboutRoute
  '/account': typeof AccountRoute
  '/contact': typeof ContactRoute
  '/login': typeof LoginRoute
  '/payment-page': typeof PaymentPageRoute
  '/register': typeof RegisterRoute
  '/scraping-order': typeof ScrapingOrderRoute
  '/scraping-order-target': typeof ScrapingOrderTargetRoute
  '/scraping-orders': typeof ScrapingOrdersRoute
  '/test': typeof TestRoute
  '/cleaned-data/$orderId': typeof CleanedDataOrderIdRoute
  '/order-details/$orderId': typeof OrderDetailsOrderIdRoute
}

export interface FileRoutesByTo {
  '/': typeof IndexRoute
  '/about': typeof AboutRoute
  '/account': typeof AccountRoute
  '/contact': typeof ContactRoute
  '/login': typeof LoginRoute
  '/payment-page': typeof PaymentPageRoute
  '/register': typeof RegisterRoute
  '/scraping-order': typeof ScrapingOrderRoute
  '/scraping-order-target': typeof ScrapingOrderTargetRoute
  '/scraping-orders': typeof ScrapingOrdersRoute
  '/test': typeof TestRoute
  '/cleaned-data/$orderId': typeof CleanedDataOrderIdRoute
  '/order-details/$orderId': typeof OrderDetailsOrderIdRoute
}

export interface FileRoutesById {
  __root__: typeof rootRoute
  '/': typeof IndexRoute
  '/about': typeof AboutRoute
  '/account': typeof AccountRoute
  '/contact': typeof ContactRoute
  '/login': typeof LoginRoute
  '/payment-page': typeof PaymentPageRoute
  '/register': typeof RegisterRoute
  '/scraping-order': typeof ScrapingOrderRoute
  '/scraping-order-target': typeof ScrapingOrderTargetRoute
  '/scraping-orders': typeof ScrapingOrdersRoute
  '/test': typeof TestRoute
  '/cleaned-data/$orderId': typeof CleanedDataOrderIdRoute
  '/order-details/$orderId': typeof OrderDetailsOrderIdRoute
}

export interface FileRouteTypes {
  fileRoutesByFullPath: FileRoutesByFullPath
  fullPaths:
    | '/'
    | '/about'
    | '/account'
    | '/contact'
    | '/login'
    | '/payment-page'
    | '/register'
    | '/scraping-order'
    | '/scraping-order-target'
    | '/scraping-orders'
    | '/test'
    | '/cleaned-data/$orderId'
    | '/order-details/$orderId'
  fileRoutesByTo: FileRoutesByTo
  to:
    | '/'
    | '/about'
    | '/account'
    | '/contact'
    | '/login'
    | '/payment-page'
    | '/register'
    | '/scraping-order'
    | '/scraping-order-target'
    | '/scraping-orders'
    | '/test'
    | '/cleaned-data/$orderId'
    | '/order-details/$orderId'
  id:
    | '__root__'
    | '/'
    | '/about'
    | '/account'
    | '/contact'
    | '/login'
    | '/payment-page'
    | '/register'
    | '/scraping-order'
    | '/scraping-order-target'
    | '/scraping-orders'
    | '/test'
    | '/cleaned-data/$orderId'
    | '/order-details/$orderId'
  fileRoutesById: FileRoutesById
}

export interface RootRouteChildren {
  IndexRoute: typeof IndexRoute
  AboutRoute: typeof AboutRoute
  AccountRoute: typeof AccountRoute
  ContactRoute: typeof ContactRoute
  LoginRoute: typeof LoginRoute
  PaymentPageRoute: typeof PaymentPageRoute
  RegisterRoute: typeof RegisterRoute
  ScrapingOrderRoute: typeof ScrapingOrderRoute
  ScrapingOrderTargetRoute: typeof ScrapingOrderTargetRoute
  ScrapingOrdersRoute: typeof ScrapingOrdersRoute
  TestRoute: typeof TestRoute
  CleanedDataOrderIdRoute: typeof CleanedDataOrderIdRoute
  OrderDetailsOrderIdRoute: typeof OrderDetailsOrderIdRoute
}

const rootRouteChildren: RootRouteChildren = {
  IndexRoute: IndexRoute,
  AboutRoute: AboutRoute,
  AccountRoute: AccountRoute,
  ContactRoute: ContactRoute,
  LoginRoute: LoginRoute,
  PaymentPageRoute: PaymentPageRoute,
  RegisterRoute: RegisterRoute,
  ScrapingOrderRoute: ScrapingOrderRoute,
  ScrapingOrderTargetRoute: ScrapingOrderTargetRoute,
  ScrapingOrdersRoute: ScrapingOrdersRoute,
  TestRoute: TestRoute,
  CleanedDataOrderIdRoute: CleanedDataOrderIdRoute,
  OrderDetailsOrderIdRoute: OrderDetailsOrderIdRoute,
}

export const routeTree = rootRoute
  ._addFileChildren(rootRouteChildren)
  ._addFileTypes<FileRouteTypes>()

/* prettier-ignore-end */

/* ROUTE_MANIFEST_START
{
  "routes": {
    "__root__": {
      "filePath": "__root.tsx",
      "children": [
        "/",
        "/about",
        "/account",
        "/contact",
        "/login",
        "/payment-page",
        "/register",
        "/scraping-order",
        "/scraping-order-target",
        "/scraping-orders",
        "/test",
        "/cleaned-data/$orderId",
        "/order-details/$orderId"
      ]
    },
    "/": {
      "filePath": "index.tsx"
    },
    "/about": {
      "filePath": "about.tsx"
    },
    "/account": {
      "filePath": "account.tsx"
    },
    "/contact": {
      "filePath": "contact.tsx"
    },
    "/login": {
      "filePath": "login.tsx"
    },
    "/payment-page": {
      "filePath": "payment-page.tsx"
    },
    "/register": {
      "filePath": "register.tsx"
    },
    "/scraping-order": {
      "filePath": "scraping-order.tsx"
    },
    "/scraping-order-target": {
      "filePath": "scraping-order-target.tsx"
    },
    "/scraping-orders": {
      "filePath": "scraping-orders.tsx"
    },
    "/test": {
      "filePath": "test.tsx"
    },
    "/cleaned-data/$orderId": {
      "filePath": "cleaned-data.$orderId.tsx"
    },
    "/order-details/$orderId": {
      "filePath": "order-details.$orderId.tsx"
    }
  }
}
ROUTE_MANIFEST_END */
